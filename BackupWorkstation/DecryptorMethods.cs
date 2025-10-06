using Microsoft.Data.Sqlite;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Runtime.Versioning;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;

namespace BackupWorkstation
{
    [SupportedOSPlatform("windows")]
    public static class DecryptorMethods
    {
        // --- Browser password export helpers ---
        public static async Task ExportBrowserPasswordsAsync(string browserName, string backupPath)
        {
            string basePath = browserName switch
            {
                "Chrome" => Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), @"Google\Chrome\User Data"),
                "Edge" => Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), @"Microsoft\Edge\User Data"),
                _ => throw new ArgumentException("Unsupported browser")
            };

            string loginDataPath = Path.Combine(basePath, @"Default\Login Data");
            string localStatePath = Path.Combine(basePath, "Local State");
            string outputCsv = Path.Combine(backupPath, $"{browserName}Passwords.csv");

            if (!File.Exists(loginDataPath) || !File.Exists(localStatePath))
            {
                Logger.Log($"⚠ {browserName} password files not found at expected paths.");
                return;
            }

            string tempDb = Path.Combine(Path.GetTempPath(), $"{browserName}_LoginData_{Guid.NewGuid():N}.db");
            byte[]? aesKey = null;

            try
            {
                aesKey = await GetDecryptedKeyAsync(localStatePath);
                Logger.Log($"Export: obtained AES key len={(aesKey?.Length ?? 0)}");

                if (aesKey == null || aesKey.Length != 32)
                {
                    Logger.Log($"❌ {browserName} AES key invalid length: {(aesKey?.Length ?? 0)}; expected 32 bytes.");
                    return;
                }

                File.Copy(loginDataPath, tempDb, true);
                if (!File.Exists(tempDb))
                {
                    Logger.Log($"❌ Failed to copy Login Data to temp DB: {tempDb}");
                    return;
                }

                Logger.Log($"Export: opened temp DB at {tempDb}");

                using var conn = new SqliteConnection($"Data Source={tempDb};Mode=ReadOnly;Cache=Shared");
                conn.Open();

                using var cmd = new SqliteCommand("SELECT origin_url, username_value, password_value FROM logins", conn);
                using var reader = cmd.ExecuteReader();

                using var writer = new StreamWriter(outputCsv, false, Encoding.UTF8);
                writer.WriteLine("URL,Username,Password");

                int exported = 0;
                int failed = 0;

                // Reader loop per line
                int decryptedCount = 0;
                int writtenCount = 0;
                int failedDecryptCount = 0;

                while (reader.Read())
                {
                    string url = reader.IsDBNull(0) ? string.Empty : reader.GetString(0);
                    string username = reader.IsDBNull(1) ? string.Empty : reader.GetString(1);
                    byte[] encryptedPassword = reader.IsDBNull(2) ? Array.Empty<byte>() : (byte[])reader["password_value"];

                    // Use exhaustive variant tester (keeps all keys local)
                    var diag = TryExhaustiveDecrypt(encryptedPassword, aesKey!, url);

                    string password;
                    if (diag.Success)
                    {
                        decryptedCount++;
                        exported++;
                        // diag.PlainText may be empty for blank passwords
                        password = diag.PlainText ?? string.Empty;
                    }
                    else
                    {
                        failedDecryptCount++;
                        password = "[UNABLE TO DECRYPT]";
                        Logger.Log($"❌ Decryption failed for {url}: {diag.Error} | Iv:{diag.IvHex} Tag:{diag.TagHex} Ct:{diag.CtHexSample}");
                    }

                    try
                    {
                        writer.WriteLine($"{CsvEscape(url)},{CsvEscape(username)},{CsvEscape(password)}");
                        writtenCount++;
                    }
                    catch (Exception rowEx)
                    {
                        Logger.Log($"⚠ Failed writing CSV row for {url}: {rowEx.Message}");
                    }
                }

                Logger.Log($"🔐 Export summary: decrypted={decryptedCount} failedDecrypts={failedDecryptCount} rowsWritten={writtenCount}");

                writer.Flush();
                Logger.Log($"🔐 Exported {exported} {browserName} password entries to: {outputCsv} (failed: {failed})");
            }
            catch (Exception ex)
            {
                Logger.Log($"❌ Failed to export {browserName} passwords: {ex.Message}");
            }
            finally
            {
                // clear sensitive key material
                if (aesKey != null)
                {
                    Array.Clear(aesKey, 0, aesKey.Length);
                }

                // Ensure all handles released before attempting delete
                try
                {
                    GC.Collect();
                    GC.WaitForPendingFinalizers();
                    Thread.Sleep(100);

                    if (File.Exists(tempDb))
                    {
                        // retry delete in a small loop if locked
                        for (int i = 0; i < 3; i++)
                        {
                            try
                            {
                                File.Delete(tempDb);
                                Logger.Log($"Cleanup: deleted temp DB {tempDb}");
                                break;
                            }
                            catch (IOException)
                            {
                                Thread.Sleep(100);
                            }
                        }
                    }
                }
                catch (Exception ex)
                {
                    Logger.Log($"Cleanup: failed to delete temp DB {tempDb}: {ex.Message}");
                }
            }
        }

        private static string CsvEscape(string s)
        {
            if (s == null) return "\"\"";
            string escaped = s.Replace("\"", "\"\"");
            return $"\"{escaped}\"";
        }

        // Decrypt Chrome/Edge password using AES-GCM
        private static async Task<byte[]?> GetDecryptedKeyAsync(string localStatePath)
        {
            try
            {
                using var stream = File.OpenRead(localStatePath);
                using var doc = await JsonDocument.ParseAsync(stream);

                if (!doc.RootElement.TryGetProperty("os_crypt", out var osCrypt) ||
                    !osCrypt.TryGetProperty("encrypted_key", out var encryptedKeyElem))
                {
                    Logger.Log($"GetDecryptedKey: missing os_crypt/encrypted_key in {localStatePath}");
                    return null;
                }

                string encryptedKeyBase64 = encryptedKeyElem.GetString() ?? string.Empty;
                if (string.IsNullOrWhiteSpace(encryptedKeyBase64))
                {
                    Logger.Log("GetDecryptedKey: encrypted_key was empty");
                    return null;
                }

                byte[] encryptedKey;
                try
                {
                    encryptedKey = Convert.FromBase64String(encryptedKeyBase64);
                }
                catch (FormatException fex)
                {
                    Logger.Log($"GetDecryptedKey: base64 decode failed: {fex.Message}");
                    return null;
                }

                const string dpapiPrefix = "DPAPI";
                var prefixBytes = Encoding.ASCII.GetBytes(dpapiPrefix);
                if (encryptedKey.Length <= prefixBytes.Length ||
                    !encryptedKey.Take(prefixBytes.Length).SequenceEqual(prefixBytes))
                {
                    Logger.Log("GetDecryptedKey: encrypted_key does not start with expected DPAPI prefix");
                    return null;
                }

                byte[] dpapiBlob = encryptedKey.Skip(prefixBytes.Length).ToArray();
                Logger.Log($"GetDecryptedKey: dpapi blob len={dpapiBlob.Length}");

                byte[]? unprotected;
                try
                {
                    unprotected = ProtectedData.Unprotect(dpapiBlob, null, DataProtectionScope.CurrentUser);
                }
                catch (Exception ex)
                {
                    Logger.Log($"GetDecryptedKey: ProtectedData.Unprotect failed: {ex.Message}");
                    return null;
                }
                finally
                {
                    Array.Clear(dpapiBlob, 0, dpapiBlob.Length);
                }

                if (unprotected == null)
                {
                    Logger.Log("GetDecryptedKey: unprotected is null");
                    return null;
                }

                if (unprotected.Length != 32)
                {
                    Logger.Log($"GetDecryptedKey: unexpected key length={unprotected.Length}; Chrome expects 32 bytes. Aborting.");
                    Array.Clear(unprotected, 0, unprotected.Length);
                    return null;
                }

                string sample = BitConverter.ToString(unprotected, 0, Math.Min(8, unprotected.Length)).Replace("-", "");
                Logger.Log($"GetDecryptedKey: success key len={unprotected.Length} sample={sample}");
                return unprotected;
            }
            catch (Exception ex)
            {
                Logger.Log($"GetDecryptedKey: unexpected error: {ex.Message}");
                return null;
            }
        }

        // --- Decrypt result structure for diagnostics ---
        public class ChromeDecryptResult
        {
            public bool Success { get; set; }
            public string? PlainText { get; set; }
            public string? Error { get; set; }
            public string? IvHex { get; set; }
            public string? TagHex { get; set; }
            public string? CtHexSample { get; set; }
        }

        // Decrypt Chrome/Edge password blob using AES-GCM
        // Call: TryExhaustiveDecrypt(blob, aesKey, origin)
        public static ChromeDecryptResult TryExhaustiveDecrypt(byte[] blob, byte[] aesKey, string origin = "")
        {
            static string Hex(byte[]? b, int n = 12) => b == null || b.Length == 0 ? "<empty>" : BitConverter.ToString(b.Take(n).ToArray()).Replace("-", "");
            if (blob == null || blob.Length == 0) return new ChromeDecryptResult { Success = false, Error = "blob len=0" };

            // IV is expected 12 bytes for Chrome; keep 16 as a defensive candidate but 12 is primary
            int[] ivCandidates = { 12, 16 };
            int[] tagCandidates = { 16 }; // Chrome uses 16-byte GCM tag; keep single candidate to avoid noisy attempts
            bool[] tagPositionsTrailing = { true, false }; // true => tag at end, false => tag after IV

            // AAD options: null (none), 3-byte ascii prefix if present, first 3 bytes, empty, first 4 bytes
            byte[] prefix = blob.Length >= 3 ? Encoding.ASCII.GetBytes(Encoding.ASCII.GetString(blob, 0, 3)) : Array.Empty<byte>();
            var aadOptions = new List<byte[]?>() { null, prefix, blob.Take(3).ToArray(), Array.Empty<byte>(), blob.Take(4).ToArray() };

            for (int ivLenIdx = 0; ivLenIdx < ivCandidates.Length; ivLenIdx++)
                for (int tagLenIdx = 0; tagLenIdx < tagCandidates.Length; tagLenIdx++)
                    for (int tagPosIdx = 0; tagPosIdx < tagPositionsTrailing.Length; tagPosIdx++)
                    {
                        int ivLen = ivCandidates[ivLenIdx];
                        int tagLen = tagCandidates[tagLenIdx];
                        bool tagTrailing = tagPositionsTrailing[tagPosIdx];

                        // minimal sanity length check
                        if (blob.Length < ivLen + tagLen + 1) continue;

                        // offset = 3 if blob starts with ASCII 'v' (version prefix), else 0
                        int offset = (blob.Length >= 3 && blob[0] == (byte)'v') ? 3 : 0;

                        // defensive: ensure we won't slice past blob bounds
                        if (offset + ivLen > blob.Length) continue;

                        byte[] iv = blob.Skip(offset).Take(ivLen).ToArray();
                        byte[] tag;
                        byte[] ciphertext;

                        if (tagTrailing)
                        {
                            if (blob.Length < tagLen) continue;
                            tag = blob.Skip(blob.Length - tagLen).Take(tagLen).ToArray();
                            int ctStart = offset + ivLen;
                            int ctLen = Math.Max(0, blob.Length - ctStart - tagLen);
                            ciphertext = blob.Skip(ctStart).Take(ctLen).ToArray();
                        }
                        else
                        {
                            // tag immediately after IV
                            if (offset + ivLen + tagLen > blob.Length) continue;
                            tag = blob.Skip(offset + ivLen).Take(tagLen).ToArray();
                            ciphertext = blob.Skip(offset + ivLen + tagLen).Take(Math.Max(0, blob.Length - (offset + ivLen + tagLen))).ToArray();
                        }

                        foreach (var aad in aadOptions)
                        {
                            ReadOnlySpan<byte> aadSpan = aad is null ? ReadOnlySpan<byte>.Empty : aad.AsSpan();

                            try
                            {
                                if (ciphertext.Length == 0)
                                {
                                    Logger.Log($"EXH: origin={origin} ivLen={ivLen} tagLen={tagLen} tagTrailing={tagTrailing} aad={(aad == null ? "<none>" : Hex(aad, 8))} => EMPTY_PLAINTEXT");
                                    Logger.Log($"→ FullBlob: {BitConverter.ToString(blob)}");
                                    Logger.Log($"→ IV: {BitConverter.ToString(iv)}");
                                    Logger.Log($"→ CT: {BitConverter.ToString(ciphertext)}");
                                    Logger.Log($"→ TAG: {BitConverter.ToString(tag)}");
                                    return new ChromeDecryptResult { Success = true, PlainText = string.Empty, IvHex = Hex(iv), TagHex = Hex(tag), CtHexSample = Hex(ciphertext) };
                                }

                                // Replace this line:
                                // using var aesGcm = new AesGcm(aesKey);
                                // With this line (specifying the required tag size, which for Chrome/Edge is 16 bytes):
                                using var aesGcm = new AesGcm(aesKey, 16);
                                byte[] plaintext = new byte[ciphertext.Length];
                                aesGcm.Decrypt(iv, ciphertext, tag, plaintext, aadSpan);
                                string pt = Encoding.UTF8.GetString(plaintext);

                                Logger.Log($"EXH: origin={origin} SUCCESS ivLen={ivLen} tagLen={tagLen} tagTrailing={tagTrailing} aad={(aad == null ? "<none>" : Hex(aad, 8))} ptSample=\"{(pt.Length > 64 ? pt.Substring(0, 64) : pt)}\"");
                                Logger.Log($"→ FullBlob: {BitConverter.ToString(blob)}");
                                Logger.Log($"→ IV: {BitConverter.ToString(iv)}");
                                Logger.Log($"→ CT: {BitConverter.ToString(ciphertext)}");
                                Logger.Log($"→ TAG: {BitConverter.ToString(tag)}");

                                return new ChromeDecryptResult { Success = true, PlainText = pt, IvHex = Hex(iv), TagHex = Hex(tag), CtHexSample = Hex(ciphertext) };
                            }
                            catch (Exception ex)
                            {
                                // Detailed failure logging including full IV, CT and TAG for later analysis
                                Logger.Log($"EXH FAIL: origin={origin} ivLen={ivLen} tagLen={tagLen} tagTrailing={tagTrailing} aad={(aad == null ? "<none>" : Hex(aad, 8))}");
                                Logger.Log($"→ FullBlob: {BitConverter.ToString(blob)}");
                                Logger.Log($"→ IV: {BitConverter.ToString(iv)}");
                                Logger.Log($"→ CT: {BitConverter.ToString(ciphertext)}");
                                Logger.Log($"→ TAG: {BitConverter.ToString(tag)}");
                                Logger.Log($"→ Error: {ex.Message}");
                            }
                        }
                    }
            return new ChromeDecryptResult { Success = false, Error = "exhaustive variants failed" };
        }

        // --- DPAPI diagnostics ---
        // Call: DpapiDiagnostics.CheckDpapiReadiness(out string message)
        // Returns: bool success, and out message with details
        public static class DpapiDiagnostics
        {
            public static bool CheckDpapiReadiness(out string message)
            {
                try
                {
                    byte[] testData = Encoding.UTF8.GetBytes("DPAPI test");
                    byte[] encrypted = ProtectedData.Protect(testData, null, DataProtectionScope.CurrentUser);
                    byte[] decrypted = ProtectedData.Unprotect(encrypted, null, DataProtectionScope.CurrentUser);

                    bool success = Encoding.UTF8.GetString(decrypted) == "DPAPI test";
                    message = success ? "✅ DPAPI appears functional for the current user." :
                                        "⚠️ DPAPI test completed but returned unexpected result.";
                    return success;
                }
                catch (Exception ex)
                {
                    message = $"❌ DPAPI unwrap failed — account may be passwordless, corrupted, or misconfigured. Exception: {ex.Message}";
                    return false;
                }
            }
        }
    }
}
