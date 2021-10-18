#region License
//------------------------------------------------------------------------------
// Copyright (c) Dmitrii Evdokimov
// Source https://github.com/diev/
// 
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
// http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//------------------------------------------------------------------------------
#endregion

using System;
using System.Configuration;
using System.Diagnostics;
using System.IO;
using System.Reflection;
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;

namespace ACL2readonly
{
    //:: Установка прав на архив
    //icacls "path" /deny "principal":(DE) /t /c

    internal class Program
    {
        //counters
        private static int _totalDirs = 0;
        private static int _totalFiles = 0;
        private static int _newDirs = 0;
        private static int _newFiles = 0;
        private static int _renDirs = 0;
        private static int _renFiles = 0;
        private static int _renDirsE = 0;
        private static int _renFilesE = 0;
        private static int _level = 0;
        private static int _maxLevel = 0;
        private static int _errors = 0;

        //app.config
        private static readonly string _path = ConfigurationManager.AppSettings["Path"];
        private static readonly string _deny = ConfigurationManager.AppSettings["Deny"];
        private static string _log = ConfigurationManager.AppSettings["Log"];
        private static string _logE;

        //deny rights
        private static readonly FileSystemRights _dirDeny = FileSystemRights.Delete | FileSystemRights.DeleteSubdirectoriesAndFiles;
        private static readonly FileSystemRights _fileDeny = FileSystemRights.Delete | FileSystemRights.Write;

        //cut basepath
        private static readonly int _cut = _path.LastIndexOf(Path.DirectorySeparatorChar) + 1;

        //switch logic
        private static readonly bool _doRights = !string.IsNullOrEmpty(_deny);

        private static void Main(string[] args)
        {
            try
            {
                Console.WriteLine(Banner());

                var logs = Directory.CreateDirectory(Path.Combine(_log, $"{DateTime.Now:yyyy}"));

                _log = Path.Combine(logs.FullName, $"{DateTime.Now:yyyyMMdd}.log");
                _logE = Path.Combine(logs.FullName, $"{DateTime.Now:yyyyMMdd}.err");

                if (!Directory.Exists(_path))
                {
                    Console.WriteLine($"Path \"{_path}\" not exists!");
                    Environment.Exit(2);
                }

                var watch = Stopwatch.StartNew();
                
                Console.WriteLine("Wait...");
                File.AppendAllText(_log, $"[{DateTime.Now:yyyy-MM-dd HH:mm}]\n");
                ProcessDir(_path);

                watch.Stop();

                StringBuilder report = new StringBuilder();
                report.AppendLine($"Execution Time: {watch.ElapsedMilliseconds} ms.");
                report.Append("Total: ");
                report.Append($"{_totalDirs} folders (+{_newDirs}, ren {_renDirs}/E{_renDirsE}), ");
                report.Append($"{_totalFiles} files (+{_newFiles}, ren {_renFiles}/E{_renFilesE}), ");
                report.Append($"{_maxLevel} levels, ");
                report.Append($"{_errors} errors");

                if (_errors > 0)
                {
                    report.Append($" (see \"{_logE}\")");
                }

                report.AppendLine(".");

                string s = report.ToString();
                Console.WriteLine($"\n{s}");
                File.AppendAllText(_log, $"{s}\n");

                Environment.Exit(0);
            }
            catch (Exception e)
            {
                Console.WriteLine(e.Message);
                File.AppendAllText(_logE, $"{e}\n\n");

                Environment.Exit(1);
            }
        }

        /// <summary>
        /// Returns a banner text for this application.
        /// </summary>
        /// <returns>String of text.</returns>
        private static string Banner()
        {
            var assembly = Assembly.GetCallingAssembly();
            var assemblyName = assembly.GetName();
            var name = assemblyName.Name;
            var version = assemblyName.Version; // Major.Minor.Build.Revision
            string build = (version.Revision > 0) ? $" build {version.Revision}" : "";
            var ver = version.ToString(3);
            var d = Attribute.GetCustomAttribute(assembly, typeof(AssemblyDescriptionAttribute)) as AssemblyDescriptionAttribute;
            var c = Attribute.GetCustomAttribute(assembly, typeof(AssemblyCopyrightAttribute)) as AssemblyCopyrightAttribute;
            string C = c.Copyright.Replace("\u00a9", "(c)");

            return $"{name} v{ver}{build} - {d.Description}\n{C}\n";
        }

        /// <summary>
        /// Processes a specified directory.
        /// </summary>
        /// <param name="file">Directory name.</param>
        private static void ProcessDir(string dir)
        {
            _totalDirs++;

            if (_level > _maxLevel)
            {
                _maxLevel = _level;
            }

            string sdir = dir.Substring(_cut) + Path.DirectorySeparatorChar;

            string d1 = Path.GetFileName(dir);
            string d2 = d1.Trim();

            while (d2.Contains(".."))
            {
                d2 = d2.Replace("..", ".");
            }

            while (d2.Contains(" ."))
            {
                d2 = d2.Replace(" .", ".");
            }

            while (d2.Contains(" ,"))
            {
                d2 = d2.Replace(" ,", ",");
            }

            while (d2.Contains("( "))
            {
                d2 = d2.Replace("( ", "(");
            }

            while (d2.Contains(" )"))
            {
                d2 = d2.Replace(" )", ")");
            }

            while (d2.Contains("  "))
            {
                d2 = d2.Replace("  ", " ");
            }

            if (!d2.Equals(d1))
            {
                string dir2 = Path.Combine(Path.GetDirectoryName(dir), d2);

                if (Directory.Exists(dir2))
                {
                    _renDirsE++;
                    File.AppendAllText(_logE, $"D2! \"{sdir}\"\n");
                }
                else
                {
                    _renDirs++;
                    File.AppendAllText(_log, $"ren \"{sdir}\" \"{d2}\"\n");
                    Directory.Move(dir, dir2);
                    dir = dir2;
                    sdir = dir.Substring(_cut) + Path.DirectorySeparatorChar;

                    //_renDirsE++;
                    //File.AppendAllText(_logE, $"D1! \"{sdir}\"\n");
                }
            }

            if (_doRights)
            {
                DirectorySecurity dirSecurity;

                try
                {
                    if (_doRights)
                    {
                        dirSecurity = Directory.GetAccessControl(dir);

                        if (NewEntry(dirSecurity))
                        {
                            _newDirs++;
                            dirSecurity.AddAccessRule(new FileSystemAccessRule(_deny, _dirDeny, AccessControlType.Deny));
                            Directory.SetAccessControl(dir, dirSecurity);

                            Console.WriteLine(sdir);
                            File.AppendAllText(_log, $"{sdir}\n");
                        }
                    }
                }
                catch (ArgumentException)
                {
                    _errors++;
                    Console.WriteLine("Error dirname! " + sdir);
                    File.AppendAllText(_logE, $"Error dirname! \"{sdir}\"\n");
                }
                catch (DirectoryNotFoundException)
                {
                    _errors++;
                    Console.WriteLine("Error dirname_! " + sdir);
                    File.AppendAllText(_logE, $"Error dirname_! \"{sdir}\"\n");
                }
                catch (Exception e)
                {
                    _errors++;
                    Console.WriteLine("Error dir! " + sdir);
                    File.AppendAllText(_logE, $"Error dir! \"{sdir}\"\n{e}\n\n");
                }
            }

            var files = Directory.EnumerateFiles(dir);

            foreach (string file in files)
            {
                ProcessFile(file);
            }

            _level++;
            var subdirs = Directory.EnumerateDirectories(dir);

            foreach (string subdir in subdirs)
            {
                ProcessDir(subdir);
            }

            _level--;
        }

        /// <summary>
        /// Processes a specified file.
        /// </summary>
        /// <param name="file">Filename.</param>
        private static void ProcessFile(string file)
        {
            _totalFiles++;

            string sfile = file.Substring(_cut);

            string f1 = Path.GetFileName(file);
            string f2 = f1.Trim();

            while (f2.Contains(".."))
            {
                f2 = f2.Replace("..", ".");
            }

            while (f2.Contains(" ."))
            {
                f2 = f2.Replace(" .", ".");
            }

            while (f2.Contains(" ,"))
            {
                f2 = f2.Replace(" ,", ",");
            }

            while (f2.Contains("( "))
            {
                f2 = f2.Replace("( ", "(");
            }

            while (f2.Contains(" )"))
            {
                f2 = f2.Replace(" )", ")");
            }

            while (f2.Contains("  "))
            {
                f2 = f2.Replace("  ", " ");
            }

            if (!f2.Equals(f1))
            {
                string file2 = Path.Combine(Path.GetDirectoryName(file), f2);
                try
                {
                    if (File.Exists(file2))
                    {
                        if (FileHashesEqual(file, file2))
                        {
                            _renFiles++;
                            File.AppendAllText(_log, $"ren(h) \"{sfile}\"\n");
                            File.Delete(file2);
                            File.Move(file, file2);
                            file = file2;
                            sfile = file.Substring(_cut);
                        }
                        else
                        {
                            //_renFilesE++;
                            //File.AppendAllText(_logE, $"F2! \"{sfile}\"\n");

                            _renFiles++;
                            File.AppendAllText(_log, $"ren(n) \"{sfile}\"\n");
                            file2 = GetFreeFilename(file2);
                            File.Move(file, file2);
                            file = file2;
                            sfile = file.Substring(_cut);

                        }
                    }
                    else
                    {
                        _renFiles++;
                        //File.AppendAllText(_log, $"ren \"{sfile}\"\n");
                        File.Move(file, file2);
                        file = file2;
                        sfile = file.Substring(_cut);
                    }
                }
                catch (Exception)
                {
                    File.AppendAllText(_log, $"use \"{sfile}\"\n");
                }
            }

            if (_doRights)
            {
                FileSecurity fileSecurity;

                try
                {
                    fileSecurity = File.GetAccessControl(file);

                    if (NewEntry(fileSecurity))
                    {
                        _newFiles++;
                        fileSecurity.AddAccessRule(new FileSystemAccessRule(_deny, _fileDeny, AccessControlType.Deny));
                        File.SetAccessControl(file, fileSecurity);

                        Console.WriteLine(sfile);
                        File.AppendAllText(_log, $"{sfile}\n");
                    }
                }
                catch (ArgumentException)
                {
                    _errors++;
                    Console.WriteLine("Error filename! " + sfile);
                    File.AppendAllText(_logE, $"Error filename! \"{sfile}\"\n");
                }
                catch (Exception e)
                {
                    _errors++;
                    Console.WriteLine("Error file! " + sfile);
                    File.AppendAllText(_logE, $"Error file! \"{sfile}\"\n{e}\n\n");
                }
            }
        }

        /// <summary>
        /// Check if a new directory requires to change rights.
        /// </summary>
        /// <param name="security"></param>
        /// <returns>True if this directory requires.</returns>
        private static bool NewEntry(in DirectorySecurity security)
        {
            var rules = security.GetAccessRules(true, true, typeof(NTAccount));

            foreach (FileSystemAccessRule rule in rules)
            {
                if (rule.AccessControlType.HasFlag(AccessControlType.Deny) &&
                    rule.IdentityReference.Value.Equals(_deny, StringComparison.OrdinalIgnoreCase) &&
                    rule.FileSystemRights.HasFlag(_dirDeny))
                {
                    return false;
                }
            }

            return true;
        }

        /// <summary>
        /// Check if a new file requires to change rights.
        /// </summary>
        /// <param name="security"></param>
        /// <returns>True if this file requires.</returns>
        private static bool NewEntry(in FileSecurity security)
        {
            var rules = security.GetAccessRules(true, true, typeof(NTAccount));

            foreach (FileSystemAccessRule rule in rules)
            {
                if (rule.AccessControlType.HasFlag(AccessControlType.Deny) &&
                    rule.IdentityReference.Value.Equals(_deny, StringComparison.OrdinalIgnoreCase) &&
                    rule.FileSystemRights.HasFlag(_fileDeny))
                {
                    return false;
                }
            }

            return true;
        }

        /// <summary>
        /// Compares contents of two files if they are equal.
        /// </summary>
        /// <param name="file1">Filename 1.</param>
        /// <param name="file2">Filename 2.</param>
        /// <returns>True if contents are equal.</returns>
        private static bool FileHashesEqual(string file1, string file2)
        {
            byte[] hash1, hash2;

            using (var hasher = MD5.Create())
            {
                using (var stream = File.OpenRead(file1))
                {
                    hash1 = hasher.ComputeHash(stream);
                }

                using (var stream = File.OpenRead(file2))
                {
                    hash2 = hasher.ComputeHash(stream);
                }
            }

            return hash1.Equals(hash2);
        }

        /// <summary>
        /// Looks for a free filename with (++counter) if there is same used.
        /// </summary>
        /// <param name="file">Filename to look.</param>
        /// <returns>New unused filename.</returns>
        private static string GetFreeFilename(string file)
        {
            string ext = Path.GetExtension(file);
            string name = Path.ChangeExtension(file, null);
            int n = 1;

            while (File.Exists($"{name} ({++n}){ext}"))
            {
            }

            return $"{name} ({n}){ext}";
        }
    }
}
