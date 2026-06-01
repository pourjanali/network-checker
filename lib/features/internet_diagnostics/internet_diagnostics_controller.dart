import 'package:flutter/foundation.dart';
import '../../core/services/internet_diagnostics_service.dart';

/// Current state status of the diagnostic engine
enum DiagnosticEngineStatus { idle, running, completed }

/// Controller that coordinates executing tests and updating diagnostic UI states.
class InternetDiagnosticsController extends ChangeNotifier {
  DiagnosticEngineStatus _engineStatus = DiagnosticEngineStatus.idle;

  // Track status of individual checks
  bool _dnsSuccess = false;
  bool _ipv4Success = false;
  bool _ipv6Success = false;
  bool _httpsSuccess = false;
  bool _dnsAnalysisSuccess = false;
  bool _tlsAnalysisSuccess = false;
  bool _domesticIpSuccess = false;
  bool _internationalIpSuccess = false;
  bool _overallInternetAccess = false;

  // Hold detailed results
  DiagnosticTestResult? _dnsResult;
  DiagnosticTestResult? _ipv4Result;
  DiagnosticTestResult? _ipv6Result;
  DiagnosticTestResult? _httpsResult;
  DnsAnalysisSummary? _dnsAnalysisSummary;
  TlsAnalysisSummary? _tlsAnalysisSummary;
  DiagnosticTestResult? _domesticIpResult;
  DiagnosticTestResult? _internationalIpResult;
  DiagnosticTestResult? _routingAnalysisResult;

  // Website Reachability State
  List<WebsiteReachabilityResult> _websiteResults = [];
  bool _isScanningWebsites = false;

  // TLS / HTTPS Analysis State
  bool _isScanningTlsTargets = false;

  // Social Media Reachability State
  List<SocialMediaResult> _socialMediaResults = [];
  bool _isScanningSocialMedia = false;

  // List of major targets to verify
  static const List<Map<String, String>> targetWebsites = [
    {'name': 'Google', 'domain': 'www.google.com'},
    {'name': 'YouTube', 'domain': 'www.youtube.com'},
    {'name': 'GitHub', 'domain': 'github.com'},
    {'name': 'Wikipedia', 'domain': 'wikipedia.org'},
    {'name': 'Reddit', 'domain': 'www.reddit.com'},
    {'name': 'Stack Overflow', 'domain': 'stackoverflow.com'},
    {'name': 'ChatGPT', 'domain': 'chatgpt.com'},
    {'name': 'Claude', 'domain': 'claude.ai'},
    {'name': 'Gemini', 'domain': 'gemini.google.com'},
  ];

  // List of social media targets to verify
  static const List<Map<String, String>> targetSocialMedia = [
    {
      'name': 'Telegram',
      'primary': 'telegram.org',
      'secondary': 'api.telegram.org',
    },
    {
      'name': 'WhatsApp',
      'primary': 'web.whatsapp.com',
      'secondary': 'graph.whatsapp.com',
    },
    {
      'name': 'Discord',
      'primary': 'discord.com',
      'secondary': 'gateway.discord.gg',
    },
    {
      'name': 'Instagram',
      'primary': 'instagram.com',
      'secondary': 'scontent.cdninstagram.com',
    },
    {'name': 'X (Twitter)', 'primary': 'x.com', 'secondary': 'api.x.com'},
    {
      'name': 'Facebook',
      'primary': 'facebook.com',
      'secondary': 'graph.facebook.com',
    },
    {'name': 'TikTok', 'primary': 'tiktok.com', 'secondary': 'api.tiktokv.com'},
    {
      'name': 'Snapchat',
      'primary': 'snapchat.com',
      'secondary': 'aws.api.snapchat.com',
    },
    {'name': 'Signal', 'primary': 'signal.org', 'secondary': 'chat.signal.org'},
  ];

  // Track progress
  int _completedTestsCount = 0;
  static const int totalTestsCount = 10; // 10 progressive sequence tasks

  // Getters
  DiagnosticEngineStatus get engineStatus => _engineStatus;
  bool get dnsSuccess => _dnsSuccess;
  bool get ipv4Success => _ipv4Success;
  bool get ipv6Success => _ipv6Success;
  bool get httpsSuccess => _httpsSuccess;
  bool get dnsAnalysisSuccess => _dnsAnalysisSuccess;
  bool get tlsAnalysisSuccess => _tlsAnalysisSuccess;
  bool get domesticIpSuccess => _domesticIpSuccess;
  bool get internationalIpSuccess => _internationalIpSuccess;
  bool get overallInternetAccess => _overallInternetAccess;

  DiagnosticTestResult? get dnsResult => _dnsResult;
  DiagnosticTestResult? get ipv4Result => _ipv4Result;
  DiagnosticTestResult? get ipv6Result => _ipv6Result;
  DiagnosticTestResult? get httpsResult => _httpsResult;
  DnsAnalysisSummary? get dnsAnalysisSummary => _dnsAnalysisSummary;
  TlsAnalysisSummary? get tlsAnalysisSummary => _tlsAnalysisSummary;
  DiagnosticTestResult? get domesticIpResult => _domesticIpResult;
  DiagnosticTestResult? get internationalIpResult => _internationalIpResult;
  DiagnosticTestResult? get routingAnalysisResult => _routingAnalysisResult;

  List<WebsiteReachabilityResult> get websiteResults => _websiteResults;
  bool get isScanningWebsites => _isScanningWebsites;
  bool get isScanningTlsTargets => _isScanningTlsTargets;

  List<SocialMediaResult> get socialMediaResults => _socialMediaResults;
  bool get isScanningSocialMedia => _isScanningSocialMedia;

  int get completedTestsCount => _completedTestsCount;
  double get progressFraction => _completedTestsCount / totalTestsCount;

  bool get isIdle => _engineStatus == DiagnosticEngineStatus.idle;
  bool get isRunning => _engineStatus == DiagnosticEngineStatus.running;
  bool get isCompleted => _engineStatus == DiagnosticEngineStatus.completed;

  // Website reachability summary statistics
  int get reachableWebsitesCount => _websiteResults
      .where((w) => w.status == ReachabilityStatus.reachable)
      .length;

  int get blockedWebsitesCount => _websiteResults
      .where((w) => w.status == ReachabilityStatus.blocked)
      .length;

  int get failedWebsitesCount => _websiteResults
      .where(
        (w) =>
            w.status == ReachabilityStatus.dnsFailure ||
            w.status == ReachabilityStatus.tlsFailure ||
            w.status == ReachabilityStatus.timeout,
      )
      .length;

  int get averageWebsiteLatencyMs {
    final latencies = _websiteResults
        .where(
          (w) =>
              w.latencyMs != null && w.status == ReachabilityStatus.reachable,
        )
        .map((w) => w.latencyMs!)
        .toList();
    if (latencies.isEmpty) return 0;
    final total = latencies.reduce((a, b) => a + b);
    return (total / latencies.length).round();
  }

  int get tlsHandshakeSuccessCount =>
      _tlsAnalysisSummary?.successfulHandshakes ?? 0;

  int get tlsCertificateMismatchCount =>
      _tlsAnalysisSummary?.certificateMismatches ?? 0;

  int get tlsTraceMismatchCount => _tlsAnalysisSummary?.traceMismatches ?? 0;

  int get averageTlsHandshakeLatencyMs =>
      _tlsAnalysisSummary?.averageHandshakeLatencyMs ?? 0;

  // Social Media accessibility summary statistics
  int get accessibleSocialCount => _socialMediaResults
      .where((w) => w.status == SocialMediaStatus.accessible)
      .length;

  int get partialSocialCount => _socialMediaResults
      .where((w) => w.status == SocialMediaStatus.partial)
      .length;

  int get blockedSocialCount => _socialMediaResults
      .where((w) => w.status == SocialMediaStatus.blocked)
      .length;

  int get averageSocialLatencyMs {
    final latencies = _socialMediaResults
        .where(
          (w) => w.latencyMs != null && w.status != SocialMediaStatus.blocked,
        )
        .map((w) => w.latencyMs!)
        .toList();
    if (latencies.isEmpty) return 0;
    final total = latencies.reduce((a, b) => a + b);
    return (total / latencies.length).round();
  }

  /// Run all tests sequentially to create a gorgeous scanning effect in the UI
  Future<void> runDiagnosticsSuite() async {
    if (_engineStatus == DiagnosticEngineStatus.running) return;

    _engineStatus = DiagnosticEngineStatus.running;
    _completedTestsCount = 0;

    _dnsSuccess = false;
    _ipv4Success = false;
    _ipv6Success = false;
    _httpsSuccess = false;
    _dnsAnalysisSuccess = false;
    _tlsAnalysisSuccess = false;
    _domesticIpSuccess = false;
    _internationalIpSuccess = false;
    _overallInternetAccess = false;

    _dnsResult = null;
    _ipv4Result = null;
    _ipv6Result = null;
    _httpsResult = null;
    _dnsAnalysisSummary = null;
    _tlsAnalysisSummary = null;
    _domesticIpResult = null;
    _internationalIpResult = null;
    _routingAnalysisResult = null;
    _websiteResults = [];
    _isScanningWebsites = false;
    _isScanningTlsTargets = false;
    _socialMediaResults = [];
    _isScanningSocialMedia = false;

    notifyListeners();

    // 1. DNS Resolution Test
    await Future<void>.delayed(const Duration(milliseconds: 400));
    _dnsResult = await InternetDiagnosticsService.checkDnsResolution();
    _dnsSuccess = _dnsResult!.success;
    _completedTestsCount++;
    notifyListeners();

    // 2. IPv4 Connectivity Test
    await Future<void>.delayed(const Duration(milliseconds: 400));
    _ipv4Result = await InternetDiagnosticsService.checkIpv4Connectivity();
    _ipv4Success = _ipv4Result!.success;
    _completedTestsCount++;
    notifyListeners();

    // 3. IPv6 Connectivity Test
    await Future<void>.delayed(const Duration(milliseconds: 400));
    _ipv6Result = await InternetDiagnosticsService.checkIpv6Connectivity();
    _ipv6Success = _ipv6Result!.success;
    _completedTestsCount++;
    notifyListeners();

    // 4. HTTPS Traffic Test
    await Future<void>.delayed(const Duration(milliseconds: 400));
    _httpsResult = await InternetDiagnosticsService.checkHttpsTraffic();
    _httpsSuccess = _httpsResult!.success;
    _completedTestsCount++;
    notifyListeners();

    // 5. DNS Provider Analysis
    await Future<void>.delayed(const Duration(milliseconds: 400));
    _dnsAnalysisSummary =
        await InternetDiagnosticsService.analyzeDnsProviders();
    _dnsAnalysisSuccess = _dnsAnalysisSummary!.success;
    _completedTestsCount++;
    notifyListeners();

    // 6. Domestic IP Discovery Test
    await Future<void>.delayed(const Duration(milliseconds: 400));
    _domesticIpResult = await InternetDiagnosticsService.fetchPublicIp(
      domestic: true,
    );
    _domesticIpSuccess = _domesticIpResult!.success;
    _completedTestsCount++;
    notifyListeners();

    // 7. International IP Discovery Test
    await Future<void>.delayed(const Duration(milliseconds: 400));
    _internationalIpResult = await InternetDiagnosticsService.fetchPublicIp(
      domestic: false,
    );
    _internationalIpSuccess = _internationalIpResult!.success;
    _completedTestsCount++;
    notifyListeners();

    // 8. Perform IP Routing and Discrepancy Analysis
    _routingAnalysisResult = InternetDiagnosticsService.analyzePublicIps(
      domesticResult: _domesticIpResult!,
      internationalResult: _internationalIpResult!,
    );
    notifyListeners();

    // 9. TLS / HTTPS Analysis Step
    await Future<void>.delayed(const Duration(milliseconds: 400));
    _isScanningTlsTargets = true;
    _completedTestsCount++;
    notifyListeners();

    _tlsAnalysisSummary = await InternetDiagnosticsService.analyzeTlsTargets(
      publicIp:
          _extractRetrievedIp(_internationalIpResult) ??
          _extractRetrievedIp(_domesticIpResult),
    );
    _tlsAnalysisSuccess = _tlsAnalysisSummary!.success;
    _isScanningTlsTargets = false;
    notifyListeners();

    // 10. Website Reachability Scan Step
    await Future<void>.delayed(const Duration(milliseconds: 400));
    _isScanningWebsites = true;
    _completedTestsCount++;
    notifyListeners();

    for (final target in targetWebsites) {
      final name = target['name']!;
      final domain = target['domain']!;

      final result = await InternetDiagnosticsService.testWebsiteReachability(
        name,
        domain,
      );
      _websiteResults.add(result);
      notifyListeners();

      // Subtle stagger delay between sequential checks to render scanning effect
      await Future<void>.delayed(const Duration(milliseconds: 150));
    }

    _isScanningWebsites = false;
    notifyListeners();

    // 11. Social Media Accessibility Scan Step
    await Future<void>.delayed(const Duration(milliseconds: 400));
    _isScanningSocialMedia = true;
    _completedTestsCount++;
    notifyListeners();

    for (final target in targetSocialMedia) {
      final name = target['name']!;
      final primary = target['primary']!;
      final secondary = target['secondary']!;

      final result =
          await InternetDiagnosticsService.testSocialMediaAccessibility(
            name: name,
            primaryDomain: primary,
            secondaryDomain: secondary,
          );
      _socialMediaResults.add(result);
      notifyListeners();

      // Subtle stagger delay between sequential checks to render scanning effect
      await Future<void>.delayed(const Duration(milliseconds: 150));
    }

    _isScanningSocialMedia = false;

    // Compute Overall Internet Access
    _overallInternetAccess =
        _dnsSuccess ||
        _ipv4Success ||
        _ipv6Success ||
        _httpsSuccess ||
        _dnsAnalysisSuccess ||
        _tlsAnalysisSuccess ||
        _domesticIpSuccess ||
        _internationalIpSuccess ||
        _websiteResults.any((w) => w.status == ReachabilityStatus.reachable) ||
        _socialMediaResults.any(
          (s) =>
              s.status == SocialMediaStatus.accessible ||
              s.status == SocialMediaStatus.partial,
        );

    _engineStatus = DiagnosticEngineStatus.completed;
    notifyListeners();
  }

  /// Reset the engine state
  void resetSuite() {
    _engineStatus = DiagnosticEngineStatus.idle;
    _completedTestsCount = 0;

    _dnsSuccess = false;
    _ipv4Success = false;
    _ipv6Success = false;
    _httpsSuccess = false;
    _dnsAnalysisSuccess = false;
    _tlsAnalysisSuccess = false;
    _domesticIpSuccess = false;
    _internationalIpSuccess = false;
    _overallInternetAccess = false;

    _dnsResult = null;
    _ipv4Result = null;
    _ipv6Result = null;
    _httpsResult = null;
    _dnsAnalysisSummary = null;
    _tlsAnalysisSummary = null;
    _domesticIpResult = null;
    _internationalIpResult = null;
    _routingAnalysisResult = null;
    _websiteResults = [];
    _isScanningWebsites = false;
    _isScanningTlsTargets = false;
    _socialMediaResults = [];
    _isScanningSocialMedia = false;

    notifyListeners();
  }

  String? _extractRetrievedIp(DiagnosticTestResult? result) {
    if (result == null || !result.success) return null;
    return result.message.replaceFirst('IP retrieved: ', '').trim();
  }
}
