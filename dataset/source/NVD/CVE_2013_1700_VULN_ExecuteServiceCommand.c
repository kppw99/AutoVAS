BOOL
CVE_2013_1700_VULN_ExecuteServiceCommand(int argc, LPWSTR *argv)
{
  if (argc < 3) {
    LOG_WARN(("Not enough command line arguments to execute a service command"));
    return FALSE;
  }

  // The tests work by making sure the log has changed, so we put a 
  // unique ID in the log.
  RPC_WSTR guidString = RPC_WSTR(L"");
  GUID guid;
  HRESULT hr = CoCreateGuid(&guid);
  if (SUCCEEDED(hr)) {
    UuidToString(&guid, &guidString);
  }
  LOG(("Executing service command %ls, ID: %ls",
       argv[2], reinterpret_cast<LPCWSTR>(guidString)));
  RpcStringFree(&guidString);

  BOOL result = FALSE;
  if (!lstrcmpi(argv[2], L"software-update")) {

    // Use the passed in command line arguments for the update, except for the
    // path to updater.exe.  We copy updater.exe to a the directory of the
    // MozillaMaintenance service so that a low integrity process cannot
    // replace the updater.exe at any point and use that for the update.
    // It also makes DLL injection attacks harder.
    LPWSTR oldUpdaterPath = argv[3];
    WCHAR secureUpdaterPath[MAX_PATH + 1] = { L'\0' };
    result = GetSecureUpdaterPath(secureUpdaterPath); // Does its own logging
    if (result) {
      LOG(("Passed in path: '%ls'; Using this path for updating: '%ls'.",
           oldUpdaterPath, secureUpdaterPath));
      DeleteSecureUpdater(secureUpdaterPath);
      result = CopyFileW(oldUpdaterPath, secureUpdaterPath, FALSE);
      if (!result) {
        LOG_WARN(("Could not copy path to secure location.  (%d)",
                  GetLastError()));
      }
    }

    // If we obtained the path and copied it successfully update the path to
    // use for the service update.  If there was a problem use the original
    // path so things work like it used to.
    if (result) {
      argv[3] = secureUpdaterPath;

      WCHAR oldUpdaterINIPath[MAX_PATH + 1] = { L'\0' };
      WCHAR secureUpdaterINIPath[MAX_PATH + 1] = { L'\0' };
      if (PathGetSiblingFilePath(secureUpdaterINIPath, secureUpdaterPath,
                                 L"updater.ini") &&
          PathGetSiblingFilePath(oldUpdaterINIPath, oldUpdaterPath,
                                 L"updater.ini")) {
        // This is non fatal if it fails there is no real harm
        if (!CopyFileW(oldUpdaterINIPath, secureUpdaterINIPath, FALSE)) {
          LOG_WARN(("Could not copy updater.ini from: '%ls' to '%ls'.  (%d)",
                    oldUpdaterINIPath, secureUpdaterINIPath, GetLastError()));
        }
      }
    }

    result = ProcessSoftwareUpdateCommand(argc - 3, argv + 3);
    DeleteSecureUpdater(secureUpdaterPath);

    // We might not reach here if the service install succeeded
    // because the service self updates itself and the service
    // installer will stop the service.
    LOG(("Service command %ls complete.", argv[2]));
  } else {
    LOG_WARN(("Service command not recognized: %ls.", argv[2]));
    // result is already set to FALSE
  }

  LOG(("service command %ls complete with result: %ls.",
       argv[1], (result ? L"Success" : L"Failure")));
  return TRUE;
}
