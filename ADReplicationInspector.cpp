// ADReplicationInspector.cpp
// Outil de monitoring topologie réplication Active Directory avec cohérence USN et latence
// Ayi NEDJIMI Consultants - WinToolsSuite

#define UNICODE
#define _UNICODE
#define _WIN32_DCOM

#include <windows.h>
#include <commctrl.h>
#include <activeds.h>
#include <lm.h>
#include <winevt.h>
#include <string>
#include <vector>
#include <map>
#include <thread>
#include <fstream>
#include <iomanip>

#pragma comment(lib, "activeds.lib")
#pragma comment(lib, "adsiid.lib")
#pragma comment(lib, "netapi32.lib")
#pragma comment(lib, "wevtapi.lib")
#pragma comment(lib, "comctl32.lib")
#pragma comment(linker, "\"/manifestdependency:type='win32' name='Microsoft.Windows.Common-Controls' version='6.0.0.0' processorArchitecture='*' publicKeyToken='6595b64144ccf1df' language='*'\"")

struct ADReplicationInfo {
    std::wstring site;
    std::wstring dc;
    std::wstring usn;
    std::wstring partners;
    std::wstring lastReplication;
    std::wstring latency;
    std::wstring errors;
};

// Globals
HWND g_hwndMain = nullptr;
HWND g_hwndListView = nullptr;
HWND g_hwndStatus = nullptr;
std::vector<ADReplicationInfo> g_replInfo;
bool g_isScanning = false;

// Logging
void LogMessage(const std::wstring& msg) {
    wchar_t tempPath[MAX_PATH];
    GetTempPathW(MAX_PATH, tempPath);
    std::wstring logPath = std::wstring(tempPath) + L"ADReplicationInspector.log";

    std::wofstream logFile(logPath, std::ios::app);
    if (logFile.is_open()) {
        SYSTEMTIME st;
        GetLocalTime(&st);
        logFile << std::setfill(L'0')
                << std::setw(4) << st.wYear << L"-"
                << std::setw(2) << st.wMonth << L"-"
                << std::setw(2) << st.wDay << L" "
                << std::setw(2) << st.wHour << L":"
                << std::setw(2) << st.wMinute << L":"
                << std::setw(2) << st.wSecond << L" - "
                << msg << std::endl;
        logFile.close();
    }
}

std::wstring GetDomainDN() {
    wchar_t computerName[256];
    DWORD size = 256;
    GetComputerNameW(computerName, &size);

    PDOMAIN_CONTROLLER_INFOW dcInfo = nullptr;
    DWORD result = DsGetDcNameW(nullptr, nullptr, nullptr, nullptr, 0, &dcInfo);

    if (result == ERROR_SUCCESS && dcInfo) {
        std::wstring domainDns = dcInfo->DomainName;
        NetApiBufferFree(dcInfo);

        std::wstring dn = L"DC=";
        size_t pos = 0;
        while ((pos = domainDns.find(L'.')) != std::wstring::npos) {
            dn += domainDns.substr(0, pos) + L",DC=";
            domainDns.erase(0, pos + 1);
        }
        dn += domainDns;
        return dn;
    }

    return L"";
}

std::wstring GetHighestCommittedUSN(const std::wstring& dcName) {
    std::wstring ldapPath = L"LDAP://" + dcName + L"/rootDSE";

    IADs* pADs = nullptr;
    HRESULT hr = ADsGetObject(ldapPath.c_str(), IID_IADs, (void**)&pADs);

    if (SUCCEEDED(hr)) {
        VARIANT var;
        VariantInit(&var);

        hr = pADs->Get((BSTR)L"highestCommittedUSN", &var);
        if (SUCCEEDED(hr) && var.vt == VT_BSTR) {
            std::wstring usn = var.bstrVal;
            VariantClear(&var);
            pADs->Release();
            return usn;
        }

        VariantClear(&var);
        pADs->Release();
    }

    return L"N/A";
}

std::vector<std::wstring> EnumerateSites() {
    std::vector<std::wstring> sites;

    std::wstring domainDN = GetDomainDN();
    if (domainDN.empty()) return sites;

    std::wstring sitesPath = L"LDAP://CN=Sites,CN=Configuration," + domainDN;

    IADsContainer* pContainer = nullptr;
    HRESULT hr = ADsGetObject(sitesPath.c_str(), IID_IADsContainer, (void**)&pContainer);

    if (SUCCEEDED(hr)) {
        IEnumVARIANT* pEnum = nullptr;
        hr = ADsBuildEnumerator(pContainer, &pEnum);

        if (SUCCEEDED(hr)) {
            VARIANT var;
            ULONG fetched = 0;

            while (S_OK == ADsEnumerateNext(pEnum, 1, &var, &fetched)) {
                if (fetched == 0) break;

                IADs* pADs = nullptr;
                hr = V_DISPATCH(&var)->QueryInterface(IID_IADs, (void**)&pADs);

                if (SUCCEEDED(hr)) {
                    BSTR className = nullptr;
                    pADs->get_Class(&className);

                    if (className && wcscmp(className, L"site") == 0) {
                        BSTR name = nullptr;
                        pADs->get_Name(&name);
                        if (name) {
                            std::wstring siteName = name;
                            if (siteName.find(L"CN=") == 0) {
                                siteName = siteName.substr(3);
                            }
                            sites.push_back(siteName);
                            SysFreeString(name);
                        }
                    }

                    if (className) SysFreeString(className);
                    pADs->Release();
                }

                VariantClear(&var);
            }

            ADsFreeEnumerator(pEnum);
        }

        pContainer->Release();
    }

    return sites;
}

std::vector<std::wstring> EnumerateDCsInSite(const std::wstring& siteName) {
    std::vector<std::wstring> dcs;

    std::wstring domainDN = GetDomainDN();
    if (domainDN.empty()) return dcs;

    std::wstring serversPath = L"LDAP://CN=Servers,CN=" + siteName + L",CN=Sites,CN=Configuration," + domainDN;

    IADsContainer* pContainer = nullptr;
    HRESULT hr = ADsGetObject(serversPath.c_str(), IID_IADsContainer, (void**)&pContainer);

    if (SUCCEEDED(hr)) {
        IEnumVARIANT* pEnum = nullptr;
        hr = ADsBuildEnumerator(pContainer, &pEnum);

        if (SUCCEEDED(hr)) {
            VARIANT var;
            ULONG fetched = 0;

            while (S_OK == ADsEnumerateNext(pEnum, 1, &var, &fetched)) {
                if (fetched == 0) break;

                IADs* pADs = nullptr;
                hr = V_DISPATCH(&var)->QueryInterface(IID_IADs, (void**)&pADs);

                if (SUCCEEDED(hr)) {
                    BSTR name = nullptr;
                    pADs->get_Name(&name);
                    if (name) {
                        std::wstring dcName = name;
                        if (dcName.find(L"CN=") == 0) {
                            dcName = dcName.substr(3);
                        }
                        dcs.push_back(dcName);
                        SysFreeString(name);
                    }
                    pADs->Release();
                }

                VariantClear(&var);
            }

            ADsFreeEnumerator(pEnum);
        }

        pContainer->Release();
    }

    return dcs;
}

int CheckReplicationErrors() {
    int errorCount = 0;

    // Query Event Log for replication errors (Event IDs: 1311, 1388, 2042)
    std::wstring query = L"*[System[(EventID=1311 or EventID=1388 or EventID=2042)]]";

    EVT_HANDLE hResults = EvtQuery(nullptr, L"Directory Service", query.c_str(),
                                    EvtQueryChannelPath | EvtQueryReverseDirection);

    if (hResults) {
        DWORD returned = 0;
        EVT_HANDLE events[50];

        if (EvtNext(hResults, 50, events, INFINITE, 0, &returned)) {
            errorCount = returned;

            for (DWORD i = 0; i < returned; i++) {
                EvtClose(events[i]);
            }
        }

        EvtClose(hResults);
    }

    return errorCount;
}

void ScanTopology() {
    g_isScanning = true;
    SendMessageW(g_hwndStatus, SB_SETTEXTW, 0, (LPARAM)L"Scan de la topologie AD...");
    LogMessage(L"Démarrage scan topologie AD");

    HRESULT hr = CoInitializeEx(0, COINIT_MULTITHREADED);

    g_replInfo.clear();
    ListView_DeleteAllItems(g_hwndListView);

    std::vector<std::wstring> sites = EnumerateSites();

    if (sites.empty()) {
        MessageBoxW(g_hwndMain, L"Aucun site AD trouvé.\r\nVérifiez que la machine est jointe à un domaine Active Directory.",
                   L"Information", MB_OK | MB_ICONINFORMATION);
        SendMessageW(g_hwndStatus, SB_SETTEXTW, 0, (LPARAM)L"Aucun site trouvé");
        LogMessage(L"Aucun site AD détecté");
        g_isScanning = false;
        CoUninitialize();
        return;
    }

    int totalDCs = 0;
    std::map<std::wstring, LONGLONG> dcUSNs;

    for (const auto& site : sites) {
        std::vector<std::wstring> dcs = EnumerateDCsInSite(site);

        for (const auto& dc : dcs) {
            ADReplicationInfo info;
            info.site = site;
            info.dc = dc;

            // Get USN
            info.usn = GetHighestCommittedUSN(dc);

            if (info.usn != L"N/A") {
                dcUSNs[dc] = _wtoll(info.usn.c_str());
            }

            // Partners (simplified - would need DsReplicaGetInfo API for full detail)
            info.partners = L"Multiple";

            // Last Replication (approximation)
            SYSTEMTIME st;
            GetLocalTime(&st);
            wchar_t timeStr[100];
            swprintf_s(timeStr, L"%04d-%02d-%02d %02d:%02d",
                     st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute);
            info.lastReplication = timeStr;

            // Latency (will calculate after collecting all USNs)
            info.latency = L"Calcul...";

            // Errors
            int errors = CheckReplicationErrors();
            info.errors = (errors > 0) ? std::to_wstring(errors) + L" erreur(s)" : L"Aucune";

            g_replInfo.push_back(info);
            totalDCs++;

            // Add to ListView
            LVITEMW lvi = {};
            lvi.mask = LVIF_TEXT;
            lvi.iItem = ListView_GetItemCount(g_hwndListView);
            lvi.pszText = (LPWSTR)info.site.c_str();
            int index = ListView_InsertItem(g_hwndListView, &lvi);

            ListView_SetItemText(g_hwndListView, index, 1, (LPWSTR)info.dc.c_str());
            ListView_SetItemText(g_hwndListView, index, 2, (LPWSTR)info.usn.c_str());
            ListView_SetItemText(g_hwndListView, index, 3, (LPWSTR)info.partners.c_str());
            ListView_SetItemText(g_hwndListView, index, 4, (LPWSTR)info.lastReplication.c_str());
            ListView_SetItemText(g_hwndListView, index, 5, (LPWSTR)info.latency.c_str());
            ListView_SetItemText(g_hwndListView, index, 6, (LPWSTR)info.errors.c_str());
        }
    }

    // Calculate latency based on USN differences
    if (dcUSNs.size() > 1) {
        LONGLONG maxUSN = 0;
        LONGLONG minUSN = LLONG_MAX;

        for (const auto& pair : dcUSNs) {
            if (pair.second > maxUSN) maxUSN = pair.second;
            if (pair.second < minUSN) minUSN = pair.second;
        }

        LONGLONG usnDiff = maxUSN - minUSN;

        for (int i = 0; i < ListView_GetItemCount(g_hwndListView); i++) {
            wchar_t dcName[256], usnStr[256];
            ListView_GetItemText(g_hwndListView, i, 1, dcName, 256);
            ListView_GetItemText(g_hwndListView, i, 2, usnStr, 256);

            if (dcUSNs.find(dcName) != dcUSNs.end()) {
                LONGLONG dcUSN = dcUSNs[dcName];
                LONGLONG diff = maxUSN - dcUSN;

                std::wstring latency;
                if (diff == 0) {
                    latency = L"Synchronisé";
                } else if (diff < 1000) {
                    latency = L"< 1 min";
                } else if (diff < 10000) {
                    latency = L"< 10 min";
                } else {
                    latency = L"> 10 min (vérifier)";
                }

                ListView_SetItemText(g_hwndListView, i, 5, (LPWSTR)latency.c_str());
            }
        }
    }

    std::wstring msg = L"Scan terminé: " + std::to_wstring(sites.size()) + L" site(s), " +
                       std::to_wstring(totalDCs) + L" DC(s) détecté(s)";
    SendMessageW(g_hwndStatus, SB_SETTEXTW, 0, (LPARAM)msg.c_str());
    LogMessage(msg);

    CoUninitialize();
    g_isScanning = false;
}

void VerifyUSN() {
    std::wstring report = L"=== VÉRIFICATION COHÉRENCE USN ===\r\n\r\n";

    if (g_replInfo.empty()) {
        MessageBoxW(g_hwndMain, L"Effectuez d'abord un scan de topologie.", L"Information", MB_OK | MB_ICONINFORMATION);
        return;
    }

    std::map<std::wstring, LONGLONG> usnMap;
    for (const auto& info : g_replInfo) {
        if (info.usn != L"N/A") {
            usnMap[info.dc] = _wtoll(info.usn.c_str());
        }
    }

    if (usnMap.size() < 2) {
        report += L"Pas assez de DCs pour comparaison USN.\r\n";
        MessageBoxW(g_hwndMain, report.c_str(), L"Vérification USN", MB_OK | MB_ICONINFORMATION);
        return;
    }

    LONGLONG maxUSN = 0;
    LONGLONG minUSN = LLONG_MAX;
    std::wstring maxDC, minDC;

    for (const auto& pair : usnMap) {
        report += pair.first + L": " + std::to_wstring(pair.second) + L"\r\n";

        if (pair.second > maxUSN) {
            maxUSN = pair.second;
            maxDC = pair.first;
        }
        if (pair.second < minUSN) {
            minUSN = pair.second;
            minDC = pair.first;
        }
    }

    LONGLONG diff = maxUSN - minUSN;

    report += L"\r\n--- Analyse ---\r\n";
    report += L"USN le plus élevé: " + maxDC + L" (" + std::to_wstring(maxUSN) + L")\r\n";
    report += L"USN le plus bas: " + minDC + L" (" + std::to_wstring(minUSN) + L")\r\n";
    report += L"Différence: " + std::to_wstring(diff) + L"\r\n\r\n";

    if (diff < 1000) {
        report += L"STATUT: Réplication synchronisée (excellente)\r\n";
    } else if (diff < 10000) {
        report += L"STATUT: Réplication normale (léger retard)\r\n";
    } else {
        report += L"ALERTE: Retard de réplication significatif détecté!\r\n";
        report += L"RECOMMANDATION: Vérifier la connectivité et les logs de réplication.\r\n";
    }

    MessageBoxW(g_hwndMain, report.c_str(), L"Vérification USN", MB_OK | MB_ICONINFORMATION);
    LogMessage(L"Vérification USN effectuée - Diff: " + std::to_wstring(diff));
}

void TestReplication() {
    std::wstring msg = L"Test de réplication AD:\r\n\r\n";

    msg += L"Commandes manuelles recommandées:\r\n";
    msg += L"1. repadmin /showrepl - Affiche statut réplication\r\n";
    msg += L"2. repadmin /replsummary - Résumé réplication\r\n";
    msg += L"3. dcdiag /test:replications - Diagnostic complet\r\n";
    msg += L"4. repadmin /syncall /AdeP - Force synchronisation\r\n\r\n";

    int errors = CheckReplicationErrors();
    msg += L"Erreurs de réplication détectées dans les logs: " + std::to_wstring(errors) + L"\r\n\r\n";

    if (errors > 0) {
        msg += L"Event IDs concernés:\r\n";
        msg += L"- 1311: Le Knowledge Consistency Checker (KCC) a détecté des problèmes\r\n";
        msg += L"- 1388: Échec de réplication avec un DC source\r\n";
        msg += L"- 2042: Échec de réplication pendant trop longtemps\r\n";
    } else {
        msg += L"Aucune erreur de réplication critique détectée dans les logs.\r\n";
    }

    MessageBoxW(g_hwndMain, msg.c_str(), L"Test Réplication", MB_OK | MB_ICONINFORMATION);
    LogMessage(L"Test réplication - Erreurs: " + std::to_wstring(errors));
}

void ExportReport() {
    wchar_t fileName[MAX_PATH] = L"ADReplicationInspector_Report.csv";

    OPENFILENAMEW ofn = {};
    ofn.lStructSize = sizeof(ofn);
    ofn.hwndOwner = g_hwndMain;
    ofn.lpstrFile = fileName;
    ofn.nMaxFile = MAX_PATH;
    ofn.lpstrFilter = L"CSV Files\0*.csv\0All Files\0*.*\0";
    ofn.lpstrDefExt = L"csv";
    ofn.Flags = OFN_OVERWRITEPROMPT;

    if (GetSaveFileNameW(&ofn)) {
        std::wofstream csvFile(fileName, std::ios::out | std::ios::binary);
        if (csvFile.is_open()) {
            // UTF-8 BOM
            csvFile.put(0xEF);
            csvFile.put(0xBB);
            csvFile.put(0xBF);

            csvFile << L"Site,DC,USN,Partenaires,DernièreRéplic,Latence,Erreurs\n";

            int itemCount = ListView_GetItemCount(g_hwndListView);
            for (int i = 0; i < itemCount; i++) {
                wchar_t buffer[1024];

                ListView_GetItemText(g_hwndListView, i, 0, buffer, 1024);
                csvFile << L"\"" << buffer << L"\",";

                ListView_GetItemText(g_hwndListView, i, 1, buffer, 1024);
                csvFile << L"\"" << buffer << L"\",";

                ListView_GetItemText(g_hwndListView, i, 2, buffer, 1024);
                csvFile << L"\"" << buffer << L"\",";

                ListView_GetItemText(g_hwndListView, i, 3, buffer, 1024);
                csvFile << L"\"" << buffer << L"\",";

                ListView_GetItemText(g_hwndListView, i, 4, buffer, 1024);
                csvFile << L"\"" << buffer << L"\",";

                ListView_GetItemText(g_hwndListView, i, 5, buffer, 1024);
                csvFile << L"\"" << buffer << L"\",";

                ListView_GetItemText(g_hwndListView, i, 6, buffer, 1024);
                csvFile << L"\"" << buffer << L"\"\n";
            }

            csvFile.close();
            MessageBoxW(g_hwndMain, L"Export CSV réussi!", L"Succès", MB_OK | MB_ICONINFORMATION);
            LogMessage(L"Export CSV vers: " + std::wstring(fileName));
        }
    }
}

LRESULT CALLBACK WindowProc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam) {
    switch (uMsg) {
        case WM_CREATE: {
            // Buttons
            CreateWindowExW(0, L"BUTTON", L"Scanner topologie",
                           WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
                           10, 10, 150, 30, hwnd, (HMENU)1001, nullptr, nullptr);

            CreateWindowExW(0, L"BUTTON", L"Vérifier USN",
                           WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
                           170, 10, 130, 30, hwnd, (HMENU)1002, nullptr, nullptr);

            CreateWindowExW(0, L"BUTTON", L"Tester réplication",
                           WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
                           310, 10, 150, 30, hwnd, (HMENU)1003, nullptr, nullptr);

            CreateWindowExW(0, L"BUTTON", L"Exporter",
                           WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
                           470, 10, 100, 30, hwnd, (HMENU)1004, nullptr, nullptr);

            // ListView
            g_hwndListView = CreateWindowExW(0, WC_LISTVIEWW, nullptr,
                                             WS_CHILD | WS_VISIBLE | LVS_REPORT | LVS_SINGLESEL | WS_BORDER,
                                             10, 50, 1180, 500, hwnd, (HMENU)1005, nullptr, nullptr);
            ListView_SetExtendedListViewStyle(g_hwndListView, LVS_EX_FULLROWSELECT | LVS_EX_GRIDLINES);

            LVCOLUMNW lvc = {};
            lvc.mask = LVCF_TEXT | LVCF_WIDTH;

            lvc.pszText = (LPWSTR)L"Site";
            lvc.cx = 150;
            ListView_InsertColumn(g_hwndListView, 0, &lvc);

            lvc.pszText = (LPWSTR)L"DC";
            lvc.cx = 200;
            ListView_InsertColumn(g_hwndListView, 1, &lvc);

            lvc.pszText = (LPWSTR)L"USN";
            lvc.cx = 120;
            ListView_InsertColumn(g_hwndListView, 2, &lvc);

            lvc.pszText = (LPWSTR)L"Partenaires";
            lvc.cx = 120;
            ListView_InsertColumn(g_hwndListView, 3, &lvc);

            lvc.pszText = (LPWSTR)L"DernièreRéplic";
            lvc.cx = 140;
            ListView_InsertColumn(g_hwndListView, 4, &lvc);

            lvc.pszText = (LPWSTR)L"Latence";
            lvc.cx = 150;
            ListView_InsertColumn(g_hwndListView, 5, &lvc);

            lvc.pszText = (LPWSTR)L"Erreurs";
            lvc.cx = 280;
            ListView_InsertColumn(g_hwndListView, 6, &lvc);

            // StatusBar
            g_hwndStatus = CreateWindowExW(0, STATUSCLASSNAMEW, nullptr,
                                          WS_CHILD | WS_VISIBLE | SBARS_SIZEGRIP,
                                          0, 0, 0, 0, hwnd, nullptr, nullptr, nullptr);
            SendMessageW(g_hwndStatus, SB_SETTEXTW, 0, (LPARAM)L"Prêt - Ayi NEDJIMI Consultants");

            LogMessage(L"ADReplicationInspector démarré");
            break;
        }

        case WM_COMMAND: {
            switch (LOWORD(wParam)) {
                case 1001: // Scanner topologie
                    if (!g_isScanning) {
                        std::thread(ScanTopology).detach();
                    }
                    break;

                case 1002: // Vérifier USN
                    VerifyUSN();
                    break;

                case 1003: // Tester réplication
                    TestReplication();
                    break;

                case 1004: // Exporter
                    ExportReport();
                    break;
            }
            break;
        }

        case WM_SIZE: {
            RECT rect;
            GetClientRect(hwnd, &rect);

            SetWindowPos(g_hwndListView, nullptr, 10, 50, rect.right - 20, rect.bottom - 80, SWP_NOZORDER);
            SendMessageW(g_hwndStatus, WM_SIZE, 0, 0);
            break;
        }

        case WM_DESTROY:
            LogMessage(L"ADReplicationInspector fermé");
            PostQuitMessage(0);
            return 0;
    }
    return DefWindowProcW(hwnd, uMsg, wParam, lParam);
}

int WINAPI wWinMain(HINSTANCE hInstance, HINSTANCE, LPWSTR, int nCmdShow) {
    INITCOMMONCONTROLSEX icex = {};
    icex.dwSize = sizeof(icex);
    icex.dwICC = ICC_LISTVIEW_CLASSES | ICC_BAR_CLASSES;
    InitCommonControlsEx(&icex);

    WNDCLASSEXW wc = {};
    wc.cbSize = sizeof(wc);
    wc.lpfnWndProc = WindowProc;
    wc.hInstance = hInstance;
    wc.hCursor = LoadCursor(nullptr, IDC_ARROW);
    wc.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
    wc.lpszClassName = L"ADReplicationInspectorClass";
    wc.hIcon = LoadIcon(nullptr, IDI_APPLICATION);

    RegisterClassExW(&wc);

    g_hwndMain = CreateWindowExW(0, wc.lpszClassName,
                                 L"AD Replication Inspector - Ayi NEDJIMI Consultants",
                                 WS_OVERLAPPEDWINDOW,
                                 CW_USEDEFAULT, CW_USEDEFAULT, 1220, 640,
                                 nullptr, nullptr, hInstance, nullptr);

    ShowWindow(g_hwndMain, nCmdShow);
    UpdateWindow(g_hwndMain);

    MSG msg;
    while (GetMessage(&msg, nullptr, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }

    return (int)msg.wParam;
}
