using System;
using System.Linq;
using nClam;
using System.IO;
using System.Diagnostics;

class Program
{
    private static ClamClient CLAM_CLIENT;
    private static readonly string MALWARE_SAMPLES_PATH = @"E:\Projects\Clones\Malwares";
    private static readonly string QUARANTINE_PATH = "Quarantine";
    private static long FILE_COUNT = 0;
    private static long CLEAN_FILES = 0;
    private static long INFECTED_FILES = 0;
    private static long ERROR_FILES = 0;
    private static long TOTAL_SCAN_SIZE = 0;

    static void Main(string[] args)
    {
        Console.Title = "Knitrix.Antivirus.Console";

        CLAM_CLIENT = new ClamClient("localhost", 3310);
        var pingResult = CLAM_CLIENT.PingAsync().Result;
        if (!pingResult)
        {
            Console.WriteLine("Scan Engine is Not Running. Press any key to exit.");
            Console.ReadKey();
            return;
        }

        Console.WriteLine("Scan Path: " + MALWARE_SAMPLES_PATH);
        PrintLog("Scanning Started.");

        var watch = new Stopwatch();
        watch.Start();

        GetDirectoryReadyForScanning(MALWARE_SAMPLES_PATH);

        watch.Stop();

        Console.WriteLine("-------------------------------------------");
        Console.WriteLine("Scan Report");
        Console.WriteLine("Total Files Scanned: " + FILE_COUNT);
        Console.WriteLine("Total Clean Files: " + CLEAN_FILES);
        Console.WriteLine("Total Infected Files: " + INFECTED_FILES);
        Console.WriteLine("Total Faulty Files: " + ERROR_FILES);
        Console.WriteLine("Total Data Scanned: " + GetFileSize(TOTAL_SCAN_SIZE));
        Console.WriteLine("Total Execution Time: " + GetTimeElapsed(watch.ElapsedMilliseconds));

        Console.ReadKey();
    }

    private static void GetDirectoryReadyForScanning(string folderPath)
    {
        // Start with drives if you have to search the entire computer.
        DirectoryInfo dirInfo = new DirectoryInfo(folderPath);

        SearchDirectoryRecursive(dirInfo);
    }

    private static void SearchDirectoryRecursive(DirectoryInfo root)
    {
        DirectoryInfo[] subDirs = null;
        FileInfo[] files = null;

        // First, process all the files directly under this folder
        if (!((root.Attributes & FileAttributes.ReparsePoint) == FileAttributes.ReparsePoint))
        {
            try
            {
                files = root.GetFiles("*.*");
            }
            // This is thrown if even one of the files requires permissions greater
            // than the application provides.
            catch (UnauthorizedAccessException e)
            {
                Console.WriteLine("Unauthorized Access " + root.FullName);
            }
            catch (DirectoryNotFoundException e)
            {
                Console.WriteLine("Directory Not Found " + root.FullName);
            }
            if (files != null)
            {
                foreach (FileInfo fi in files)
                {
                    string fileShortDescription = FileShortDescription(fi.FullName);
                    PrintLog("Current File: " + fileShortDescription);
                    ScanFile(fi.FullName);
                    Console.WriteLine(Environment.NewLine);
                    FILE_COUNT++;
                    TOTAL_SCAN_SIZE += fi.Length;
                }
            }
            // Now find all the subdirectories under this directory.
            try
            {
                subDirs = root.GetDirectories();
            }

            catch (UnauthorizedAccessException e)
            {

                Console.WriteLine("Unauthorized Access " + root.FullName);
            }
            catch (DirectoryNotFoundException e)
            {
                Console.WriteLine("Directory Not Found " + root.FullName);
            }
            catch (Exception e)
            {
                Console.WriteLine("Other Error " + root.FullName + e.Message);
            }
            if (subDirs != null)
            {
                foreach (DirectoryInfo dirInfo in subDirs)
                {

                    try
                    {
                        SearchDirectoryRecursive(dirInfo);
                    }
                    catch (PathTooLongException ex)
                    {
                        Console.WriteLine(String.Format("Path too long for file name : {0}", dirInfo.Name));
                    }
                }
            }
        }
    }

    private static void ScanFile(string fileToScan)
    {
        var scanResult = CLAM_CLIENT.ScanFileOnServerAsync(fileToScan).Result;
        switch (scanResult.Result)
        {
            case ClamScanResults.Clean:
                Console.WriteLine("The file is clean!");
                CLEAN_FILES++;
                break;
            case ClamScanResults.VirusDetected:
                Console.WriteLine("Virus Found!");
                Console.WriteLine("Virus name: {0}", scanResult.InfectedFiles.First().VirusName);
                QuarantineContainer(fileToScan);
                INFECTED_FILES++;
                break;
            case ClamScanResults.Error:
                Console.WriteLine("Woah an error occured! Error: {0}", scanResult.RawResult);
                ERROR_FILES++;
                break;
        }
    }

    private static void PrintLog(string message)
    {
        Console.WriteLine($"{DateTime.Now.ToShortTimeString()}   {message}");
    }

    private static string FileShortDescription(string fileName)
    {
        string fileShortDescription = fileName;
        if (fileName.Length > 50)
        {
            string firstTenCharacters = fileName.Substring(0, 24);
            string lastTenCharacters = fileName.Substring(fileName.Length - 24, 24);
            fileShortDescription = firstTenCharacters + "......" + lastTenCharacters;
        }
        return fileShortDescription;
    }

    private static string GetFileSize(double bytes)
    {
        string size = "0 Bytes";
        if (bytes >= 1073741824.0)
            size = string.Format("{0:##.##}", bytes / 1073741824.0) + " GB";
        else if (bytes >= 1048576.0)
            size = string.Format("{0:##.##}", bytes / 1048576.0) + " MB";
        else if (bytes >= 1024.0)
            size = string.Format("{0:##.##}", bytes / 1024.0) + " KB";
        else if (bytes > 0 && bytes < 1024.0)
            size = bytes.ToString() + " Bytes";

        return size;
    }

    private static string GetTimeElapsed(double milliSeconds)
    {
        string timeConsumed = "0 Seconds";
        if (milliSeconds >= (24 * 60 * 60 * 1000))
            timeConsumed = string.Format("{0:##.##}", milliSeconds / (24 * 60 * 60 * 1000)) + " Days";
        else if (milliSeconds >= (60 * 60 * 1000))
            timeConsumed = string.Format("{0:##.##}", milliSeconds / (60 * 60 * 1000)) + " Hours";
        else if (milliSeconds >= (60 * 1000))
            timeConsumed = string.Format("{0:##.##}", milliSeconds / (60 * 1000)) + " Minutes";
        else if (milliSeconds > 0 && milliSeconds < (60 * 1000))
            timeConsumed = string.Format("{0:##.##}", milliSeconds / 1000) + " Seconds";

        return timeConsumed;
    }

    public static void QuarantineContainer(string scannedFile)
    {
        try
        {
            string quarantineFolder = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, QUARANTINE_PATH);

            if (!Directory.Exists(quarantineFolder))
                Directory.CreateDirectory(quarantineFolder);

            string quarantinedFile = Path.Combine(quarantineFolder, Path.GetFileName(scannedFile));

            if (!File.Exists(quarantinedFile))
                File.Copy(scannedFile, quarantinedFile);
        }
        catch (Exception ex)
        {

        }
    }
}