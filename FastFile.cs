using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using Ionic.Zlib;

namespace BlackOps2Explorer
{
    public static class Helpers
    {
        // Note this MODIFIES THE GIVEN ARRAY then returns a reference to the modified array.
        public static byte[] Reverse(this byte[] b)
        {
            Array.Reverse(b);
            return b;
        }
        public static UInt32 ReadUInt32BE(this BinaryReader binRdr)
        {
            return BitConverter.ToUInt32(binRdr.ReadBytesRequired(sizeof(UInt32)).Reverse(), 0);
        }

        public static Int32 ReadInt32BE(this BinaryReader binRdr)
        {
            return BitConverter.ToInt32(binRdr.ReadBytesRequired(sizeof(Int32)).Reverse(), 0);
        }

        public static byte[] ReadBytesRequired(this BinaryReader binRdr, int byteCount)
        {
            var result = binRdr.ReadBytes(byteCount);

            if (result.Length != byteCount)
                throw new EndOfStreamException(string.Format("{0} bytes required from stream, but only {1} returned.", byteCount, result.Length));

            return result;
        }
    }

    class FastFile
    {
        internal class AssetFoundEventArgs : EventArgs
        {
            public XAsset Asset { get; private set; }

            public AssetFoundEventArgs(XAsset asset)
            {
                Asset = asset;
            }
        }

        private const long SignedMagic = 0x3030313066664154;
        private const long UnsignedMagic = 0x3030313066664154;
        private const int PCVersion = 0x94;
        private const int ScanChunkSize = 0x500000;

        private static readonly byte[] FastFileKey = new byte[]
        {
            0xB3, 0xBD, 0x6B, 0x2C,
            0x82, 0x42, 0x8D, 0x11,
            0xB8, 0x88, 0x2D, 0x4C,
            0x6D, 0x18, 0xCC, 0x79,
            0xE2, 0x70, 0x9F, 0x6B,
            0xD4, 0x39, 0x91, 0x35,
            0xFD, 0xDE, 0x14, 0xE6,
            0x8F, 0x3A, 0xBC, 0xCE
        };

        private Stream _stream;
        private BinaryReader _reader;
        private string _path = string.Empty;

        public event EventHandler<AssetFoundEventArgs> AssetFound;
        public List<XAsset> Assets { get; private set; }
        public List<string> Strings { get; private set; }
        public bool IncludeHLSL { get; set; }

        public FastFile(string path) : this(new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read))
        {
            _path = path;
        }

        private FastFile(Stream stream)
        {
            _stream = stream;
            _reader = new BinaryReader(_stream);

            Assets = new List<XAsset>();
            Strings = new List<string>();
        }

        public void Load()
        {
            // Check the TAff magic.
            long magic = _reader.ReadInt64();

            if(magic != SignedMagic && magic != UnsignedMagic)
                throw new Exception("The file is not a valid/supported fast file.");

            // Check the fast file version. 
            int version = _reader.ReadInt32BE();
            if(version != PCVersion)
                throw new Exception("The fast file version is not supported.");

            // Create a file containing the decompressed/decrypted zone file.
            string path = CreateZoneFile();

            // Close the streams.
            _reader.Close();

            // Create new streams for the zone file.
            _stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read);
            _reader = new BinaryReader(_stream);

            // Read the zone information.
            _stream.Position = 0x28;
            int numberOfStrings = _reader.ReadInt32BE();
            _stream.Position += 16;

            // Skip extra 8 bytes if string table is present.
            if (numberOfStrings != 0)
                _stream.Position += 8;

            // Skip the FF padding if a string table exists.
            byte b = _reader.ReadByte();
            while (b == 0xFF)
                b = _reader.ReadByte();
            _stream.Position--;

            // Read the string table (some reason it goes 1 over)
            for (int i = 0; i < numberOfStrings - 1; i++)
                Strings.Add(ReadASCIIZString(_reader));
        }

        private static string ReadASCIIZString(BinaryReader reader)
        {
            long pos = reader.BaseStream.Position;
            var builder = new StringBuilder();
            int index;
            while ((index = builder.ToString().IndexOf('\0')) == -1)
                builder.Append(Encoding.ASCII.GetString(reader.ReadBytes(128)));
            reader.BaseStream.Position = pos + index + 1;
            return builder.ToString().Substring(0, index);
        }

        public void Find()
        {
            Search(".bik", DefaultHandler, false, XAssetType.Raw);
            Search(".sun", DefaultHandler, true, XAssetType.Raw);
            Search(".shock", DefaultHandler, true, XAssetType.Raw);
            Search(".rmb", DefaultHandler, true, XAssetType.Raw);
            Search(".script", DefaultHandler, true, XAssetType.Raw);
            Search(".cfg", DefaultHandler, true, XAssetType.Raw);
            Search(".txt", TextHandler, true, XAssetType.Raw);
            Search(".graph", DefaultHandler, true, XAssetType.Raw);
            Search(".vision", DefaultHandler, true, XAssetType.Raw);
            Search(".gsc", DefaultHandler, false, XAssetType.Raw);
            Search(".csc", DefaultHandler, false, XAssetType.Raw);
            Search(".lua", DefaultHandler, false, XAssetType.Raw);

            if (IncludeHLSL)
            {
                Search(".hlsl", HLSLHandler, false, XAssetType.Raw);
            }

            _reader.Close();
        }
        private void HLSLHandler(string path, int nameIndex, int dataIndex, bool isRawText, XAssetType type)
        {
            // Check that the file data is not in another place.
            _stream.Position = nameIndex - 8;

            if (_reader.ReadInt32BE() != -1)
                return;

            // Read the file/data length.
            _stream.Position = nameIndex - 4;
            int length = _reader.ReadInt32BE();

            // Read the actual data.
            _stream.Position = dataIndex;
            var data = _reader.ReadBytes(length);

            // Add the entry.
            var asset = new XAsset(path, data, type, isRawText);
            Assets.Add(asset);

            // Call the event.
            if (AssetFound != null)
                AssetFound(this, new AssetFoundEventArgs(asset));
        }

        private void TextHandler(string path, int nameIndex, int dataIndex, bool isRawText, XAssetType type)
        {
            // Check that the file data is valid.
            _stream.Position = dataIndex;

            if (_reader.ReadInt32BE() == -1)
                return;

            // Perform an extra check.
            _stream.Position = nameIndex - 4;

            if(_reader.ReadInt32BE() != -1)
                return;

            // Read the file/data length.
            _stream.Position = nameIndex - 8;
            int length = _reader.ReadInt32BE();

            // Check if the length is non-zero
            if(length == 0)
                return;

            // Read the actual data.
            _stream.Position = dataIndex;
            var data = _reader.ReadBytes(length);

            // Add the entry.
            var asset = new XAsset(path, data, type, isRawText);
            Assets.Add(asset);

            // Call the event.
            if (AssetFound != null)
                AssetFound(this, new AssetFoundEventArgs(asset));
        }

        private void DefaultHandler(string path, int nameIndex, int dataIndex, bool isRawText, XAssetType type)
        {
            // Check that the file data is not in another place.
            _stream.Position = nameIndex - 4;

            if (_reader.ReadInt32BE() != -1)
                return;

            // Read the file/data length.
            _stream.Position = nameIndex - 8;
            int length = _reader.ReadInt32BE();

            // Read the actual data.
            _stream.Position = dataIndex;
            var data = _reader.ReadBytes(length);

            // Add the entry.
            var asset = new XAsset(path, data, type, isRawText);
            Assets.Add(asset);

            // Call the event.
            if (AssetFound != null)
                AssetFound(this, new AssetFoundEventArgs(asset));
        }

        private void Search(string extension, Action<string, int, int, bool, XAssetType> callback, bool isRawText, XAssetType type)
        {
            long index = 0;

            // Perform a pattern search for the extensions.
            while ((index = FindPattern(Encoding.ASCII.GetBytes(extension + '\0'), index)) != -1)
            {
                // Get the path name.
                string path = GetNameFromIndex(index + extension.Length);

                // Get the indexes for the file.
                var nameIndex = (int) (index + extension.Length - path.Length);
                var dataIndex = (int) (index + extension.Length + 1);

                // Call the handler.
                callback(path, nameIndex, dataIndex, isRawText, type);

                index++;
            }
        }

        private string GetNameFromIndex(long index)
        {
            _stream.Position = index - 1;
            byte b;
            while ((b = _reader.ReadByte()) != 0 && b != 0xFF)
                _stream.Position -= 2;
            var length = (int) (index - _stream.Position);
            return Encoding.ASCII.GetString(_reader.ReadBytes(length), 0, length);
        }

        private long FindPattern(byte[] pattern, long start = 0)
        {
            _stream.Position = start;

            int length = ScanChunkSize;

            while(_stream.Position < _stream.Length - pattern.Length)
            {
                if (_stream.Position + length >= _stream.Length)
                    length = (int)(_stream.Length - _stream.Position);

                byte[] buffer = _reader.ReadBytes(length);
                int patternIndex = 0;

                for(int i = 0; i < buffer.Length - pattern.Length; i++)
                {
                    if (buffer[i] == pattern[patternIndex])
                    {
                        patternIndex++;

                        if (patternIndex == pattern.Length)
                            return _stream.Position - length + i - patternIndex + 1;
                    }
                    else
                    {
                        patternIndex = 0;
                    }
                }

                _stream.Position -= pattern.Length - 1;
            }

            return -1;
        }

        private string CreateZoneFile()
        {
            string outputPath = Path.Combine(Path.GetDirectoryName(_path), Path.GetFileNameWithoutExtension(_path) + "-extract.dat");

            using (var outputStream = File.Create(outputPath))
            {
                // Skip the PHEEBs71 magic.
                _stream.Position += 12;

                // Initialize the IV table.
                var ivTable = new byte[16000];
                var ivCounter = new int[4];
                FillIVTable(ivTable, _reader.ReadBytes(0x20));
                SetupIVCounter(ivCounter);

                // Skip the RSA sig.
                _stream.Position += 0x100;

                int sectionIndex = 0;
                var salsa = new Salsa20 { Key = FastFileKey };

                while (true)
                {
                    // Read section size.
                    int size = _reader.ReadInt32BE();

                    // Check that we've reached the last section.
                    if (size == 0)
                        break;

                    // Get the IV for the current section.
                    salsa.IV = GetIV(sectionIndex % 4, ivTable, ivCounter);

                    // Generate a decryptor to decrypt the data.
                    var decryptor = salsa.CreateDecryptor();

                    // Decrypt the data.
                    byte[] decryptedData = decryptor.TransformFinalBlock(_reader.ReadBytes(size), 0, size);

                    // Uncompress the decrypted data.
                    byte[] uncompressedData = DeflateStream.UncompressBuffer(decryptedData);
                    outputStream.Write(uncompressedData, 0, uncompressedData.Length);

                    // Calculate the SHA-1 of the decrypted data and update the IV table.
                    using (var sha1 = SHA1.Create())
                        UpdateIVTable(sectionIndex % 4, sha1.ComputeHash(decryptedData), ivTable, ivCounter);

                    sectionIndex++;
                }
            }

            return outputPath;
        }

        private void UpdateIVTable(int index, byte[] hash, byte[] ivTable, int[] ivCounter)
        {
            for(int i = 0; i < 20; i += 5)
            {
                int value = (index + 4 * ivCounter[index]) % 800 * 5;
                for (int x = 0; x < 5; x++)
                    ivTable[4 * value + x + i] ^= hash[i + x];
            }
            ivCounter[index]++;
        }

        private byte[] GetIV(int index, byte[] ivTable, int[] ivCounter)
        {
            var iv = new byte[8];
            int arrayIndex = (index + 4 * (ivCounter[index] - 1)) % 800 * 20;
            Array.Copy(ivTable, arrayIndex, iv, 0, 8);
            return iv;
        }

        private void SetupIVCounter(int[] ivCounter)
        {
            for (int i = 0; i < 4; i++)
                ivCounter[i] = 1;
        }

        private void FillIVTable(byte[] ivTable, byte[] nameKey)
        {
            int nameKeyLength = Array.FindIndex(nameKey, b => b == 0);

            int addDiv = 0;
            for (int i = 0; i < ivTable.Length; i += nameKeyLength * 4)
            {
                for(int x = 0; x < nameKeyLength * 4; x += 4)
                {
                    if((i + addDiv) >= ivTable.Length || i + x >= ivTable.Length)
                        return;

                    if (x > 0)
                        addDiv = x / 4;
                    else
                        addDiv = 0;

                    for (int y = 0; y < 4; y++)
                        ivTable[i + x + y] = nameKey[addDiv];
                }
            }
        }
    }
}
