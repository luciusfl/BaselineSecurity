using System.Runtime.InteropServices;
using System.Text.RegularExpressions;
using Windows.Data.Xml.Dom;
using Windows.UI.Notifications;

namespace WatchDog;

internal static partial class Program
{
    private const string AppUserModelId = "Security Configuration Alert";
    private const string ToastTitle = "Security Configuration Alert";

    // Written by Audit.ps1 as the last line of SecurityAudit.log, after every check ran.
    private const string SummaryMarker = " Checks run: ";

    // HRESULT of ERROR_SHARING_VIOLATION.
    private const int SharingViolation = unchecked((int)0x80070020);
    private const long MaximumLogBytes = 1024 * 1024;

    private enum AuditLogState
    {
        Finished,
        InProgress,
        Unfinished,
        Missing
    }

    private static int Main()
    {
        var logDirectory = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
            "SecurityAudit");
        var errorFilePath = Path.Combine(logDirectory, "SecurityAuditErrors.log");
        var auditLogPath = Path.Combine(logDirectory, "SecurityAudit.log");

        try
        {
            var state = GetAuditLogState(auditLogPath);
            var found = state switch
            {
                AuditLogState.Missing => "audit log missing",
                AuditLogState.InProgress => "audit log in use by a running audit",
                _ => $"audit log {(state == AuditLogState.Finished ? "finished" : "unfinished")} (last written {File.GetLastWriteTime(auditLogPath):yyyy-MM-dd HH:mm:ss})"
            };

            if (state == AuditLogState.InProgress)
            {
                // Another audit is writing the log right now (for example an elevated
                // Audit.cmd that made the task's run stop at once). Its result is not
                // known yet; the next completed task run triggers WatchDog again.
                WriteLog($"{found}; no toast");
                return 0;
            }

            if (state is AuditLogState.Missing or AuditLogState.Unfinished)
            {
                if (IsAuditTaskRunning())
                {
                    // A newer audit run has started but has not opened its log yet (starting
                    // PowerShell can take a minute or more, for example right after the PC woke
                    // from standby). The log still holds the older run, which that new run
                    // replaces; the new run's own end triggers WatchDog again.
                    WriteLog($"{found}; audit task running; no toast");
                    return 0;
                }

                if (state == AuditLogState.Missing)
                {
                    WriteLog($"{found}; audit task not running; toast: wrote no log");
                    ShowToast(
                        ToastTitle,
                        "The last security audit wrote no log, so its result is unknown. " +
                        "The log folder may be damaged; run Install.cmd again.",
                        logDirectory);
                    return 0;
                }

                // The audit was stopped (by the task's time limit) or crashed before its
                // summary line. The failures found until then are still shown.
                var unfinishedText =
                    "The last security audit did not finish, so its result is incomplete. " +
                    "It was stopped (the scheduled task allows 45 minutes) or it failed. " +
                    "SecurityAudit.log shows the last check it reached.";
                if (File.Exists(errorFilePath))
                {
                    unfinishedText += Environment.NewLine + ReadShared(errorFilePath);
                }

                WriteLog($"{found}; audit task not running; toast: did not finish");
                ShowToast(ToastTitle, unfinishedText, auditLogPath);
                return 0;
            }

            if (!File.Exists(errorFilePath))
            {
                WriteLog($"{found}; no failures; no toast");
                return 0;
            }

            WriteLog($"{found}; failures in SecurityAuditErrors.log; toast: failures");
            ShowToast(ToastTitle, ReadShared(errorFilePath), errorFilePath);
            return 0;
        }
        catch (Exception exception)
        {
            WriteLog($"error: {exception}");
            return 1;
        }
    }

    // WatchDog's own log: one line per run with what it found and what it did, and its errors.
    // It is in the signed-in user's %LOCALAPPDATA%\SecurityAudit, because WatchDog runs as that
    // user and may only read the audit's log folder. Above 1 MB it is renamed to WatchDog.old.log
    // (replacing the previous one) and a new file is started, so the two files stay at about
    // 2 MB at most. A failure to write it never stops WatchDog.
    private static void WriteLog(string message)
    {
        try
        {
            var directory = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                "SecurityAudit");
            Directory.CreateDirectory(directory);
            var path = Path.Combine(directory, "WatchDog.log");
            var existingLog = new FileInfo(path);
            if (existingLog.Exists && existingLog.Length > MaximumLogBytes)
            {
                existingLog.MoveTo(Path.Combine(directory, "WatchDog.old.log"), overwrite: true);
            }

            File.AppendAllText(path, $"{DateTimeOffset.Now:yyyy-MM-dd HH:mm:ss.fff zzz} {message}{Environment.NewLine}");
        }
        catch (Exception)
        {
            // The log is for troubleshooting only.
        }
    }

    // Whether the scheduled audit task is running now: its most recent "started" (100) or
    // "finished" (102) event in Task Scheduler's history is a start. That history is the log
    // WatchDog's own trigger listens to, and Task Scheduler writes the start event before
    // PowerShell has even loaded, unlike the audit's log file, which can take a minute or more.
    // The Event Log service filters the events itself (XPath query); WatchDog reads the newest
    // matching one and stops, so it never loads the history, which Windows caps at 10 MB. Only
    // the last 7 days are searched, which bounds the search when there is no such event.
    // If the history cannot be read, the answer is "not running", so WatchDog reports the
    // log as before rather than hiding a problem.
    private static bool IsAuditTaskRunning()
    {
        const string channel = "Microsoft-Windows-TaskScheduler/Operational";
        const string query =
            "*[System[Provider[@Name='Microsoft-Windows-TaskScheduler'] and (EventID=100 or EventID=102)" +
            " and TimeCreated[timediff(@SystemTime) <= 604800000]]" +
            " and EventData[Data[@Name='TaskName']='\\Security Configuration Audit']]";
        const int EvtQueryChannelPath = 0x1;
        const int EvtQueryReverseDirection = 0x200;
        const int EvtRenderEventXml = 1;

        var results = EvtQuery(IntPtr.Zero, channel, query, EvtQueryChannelPath | EvtQueryReverseDirection);
        if (results == IntPtr.Zero)
        {
            return false;
        }

        try
        {
            var events = new IntPtr[1];
            if (!EvtNext(results, 1, events, 2000, 0, out var returned) || returned == 0)
            {
                return false;
            }

            var buffer = IntPtr.Zero;
            try
            {
                // First call: ask for the size of the event's XML; second call: render it.
                EvtRender(IntPtr.Zero, events[0], EvtRenderEventXml, 0, IntPtr.Zero, out var size, out _);
                if (size <= 0)
                {
                    return false;
                }

                buffer = Marshal.AllocHGlobal(size);
                if (!EvtRender(IntPtr.Zero, events[0], EvtRenderEventXml, size, buffer, out _, out _))
                {
                    return false;
                }

                var match = EventIdPattern().Match(Marshal.PtrToStringUni(buffer) ?? string.Empty);
                return match.Success && match.Groups[1].Value == "100";
            }
            finally
            {
                if (buffer != IntPtr.Zero)
                {
                    Marshal.FreeHGlobal(buffer);
                }

                EvtClose(events[0]);
            }
        }
        finally
        {
            EvtClose(results);
        }
    }

    [GeneratedRegex(@"<EventID[^>]*>(\d+)</EventID>")]
    private static partial Regex EventIdPattern();

    [DllImport("wevtapi.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern IntPtr EvtQuery(IntPtr session, string path, string query, int flags);

    [DllImport("wevtapi.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool EvtNext(IntPtr resultSet, int eventsSize, [Out] IntPtr[] events, int timeout, int flags, out int returned);

    [DllImport("wevtapi.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool EvtRender(IntPtr context, IntPtr fragment, int flags, int bufferSize, IntPtr buffer, out int bufferUsed, out int propertyCount);

    [DllImport("wevtapi.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool EvtClose(IntPtr handle);

    // A finished audit ends SecurityAudit.log with its summary line. A log without it
    // belongs to a run that was stopped or crashed, unless an audit still has the file
    // open for writing: Audit.ps1 lets others only read while it writes, so opening the
    // file with FileShare.Read fails exactly while a writer has it open. Only SYSTEM,
    // Administrators and the audit task can write the log, so no other program can make
    // a run look unfinished or still running. A reader that holds the file open does
    // not change the result, because it does not have write access.
    private static AuditLogState GetAuditLogState(string auditLogPath)
    {
        if (!File.Exists(auditLogPath))
        {
            return AuditLogState.Missing;
        }

        try
        {
            // Closed again at once, so an audit that starts now is not blocked for long.
            using var probe = new FileStream(auditLogPath, FileMode.Open, FileAccess.Read, FileShare.Read);
        }
        catch (IOException exception) when (exception.HResult == SharingViolation)
        {
            return AuditLogState.InProgress;
        }

        string? lastLine = null;
        using (var stream = new FileStream(auditLogPath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete))
        using (var reader = new StreamReader(stream))
        {
            for (var line = reader.ReadLine(); line is not null; line = reader.ReadLine())
            {
                if (line.Trim().Length > 0)
                {
                    lastLine = line;
                }
            }
        }

        return lastLine is not null && lastLine.Contains(SummaryMarker, StringComparison.Ordinal)
            ? AuditLogState.Finished
            : AuditLogState.Unfinished;
    }

    // Reads a log without blocking an audit that starts to write it at the same time.
    private static string ReadShared(string path)
    {
        using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
        using var reader = new StreamReader(stream);
        return reader.ReadToEnd();
    }
    private static void ShowToast(string title, string text, string logFilePath)
    {
        // duration="long" keeps the banner on screen for about 25 seconds instead of 5.
        // Clicking the toast or the "Open log" button opens the log file through a
        // file:/// URI (protocol activation) in the default app for .log files.
        // The link points to the current file, which the next audit replaces.
        //
        // The XML is built as one escaped string and loaded in a single call. Do not
        // cast the nodes of the loaded document to XmlElement to set values afterwards:
        // that cast throws InvalidCastException in a native AOT build on .NET 10.
        var logFileUri = EscapeXml(new Uri(logFilePath).AbsoluteUri);
        var toastXml = new XmlDocument();
        toastXml.LoadXml(
            "<toast duration=\"long\" activationType=\"protocol\" launch=\"" + logFileUri + "\">" +
            "<visual><binding template=\"ToastGeneric\">" +
            "<text>" + EscapeXml(title) + "</text>" +
            "<text>" + EscapeXml(text) + "</text>" +
            "</binding></visual>" +
            "<actions><action content=\"Open log\" activationType=\"protocol\" arguments=\"" + logFileUri + "\"/></actions>" +
            "</toast>");

        var toast = new ToastNotification(toastXml)
        {
            Priority = ToastNotificationPriority.High
        };
        var notifier = ToastNotificationManager.CreateToastNotifier(AppUserModelId);
        notifier.Show(toast);
    }

    // Escapes text for use in XML content and attribute values. Control characters other
    // than tab and line breaks are not allowed in XML, so they are dropped first.
    private static string EscapeXml(string value)
    {
        var printable = new string(value
            .Where(c => !char.IsControl(c) || c == '\t' || c == '\n' || c == '\r')
            .ToArray());
        return System.Security.SecurityElement.Escape(printable) ?? string.Empty;
    }
}