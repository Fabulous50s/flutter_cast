import 'dart:async';
import 'package:multicast_dns/multicast_dns.dart';

import 'device.dart';

const _domain = '_googlecast._tcp.local';

class CastDiscoveryService {
  static final CastDiscoveryService _instance = CastDiscoveryService._();
  CastDiscoveryService._();

  factory CastDiscoveryService() => _instance;

  MDnsClient? _client;
  bool _starting = false;
  Completer<void>? _startCompleter;

  Future<void> _ensureStarted() async {
    if (_client != null) return;

    // another call is already starting → wait for it
    if (_starting && _startCompleter != null) {
      return _startCompleter!.future;
    }

    _starting = true;
    _startCompleter = Completer();

    final c = MDnsClient();
    try {
      await c.start();
      _client = c;
      _startCompleter!.complete();
    } on OSError catch (e) {
      // errno 48 = address already in use → safe to ignore, use existing socket
      if (e.osError?.errorCode == 48) {
        // treat c as already active
        _client = c;
        _startCompleter!.complete();
      } else {
        _startCompleter!.completeError(e);
        rethrow;
      }
    } finally {
      _starting = false;
    }
  }

  Future<List<CastDevice>> search(
      {Duration timeout = const Duration(seconds: 5)}) async {
    await _ensureStarted();
    final client = _client!;
    final results = <CastDevice>[];

    await for (PtrResourceRecord ptr in client.lookup<PtrResourceRecord>(
      ResourceRecordQuery.serverPointer(_domain),
      timeout: timeout,
    )) {
      if (results.any((x) => x.serviceName == ptr.domainName)) {
        continue;
      }

      await for (final srv in client.lookup<SrvResourceRecord>(
        ResourceRecordQuery.service(ptr.domainName),
      )) {
        final serviceName = ptr.domainName;
        final port = srv.port;
        String host = srv.target;
        Map<String, String>? extras;

        String? nameFromExtras;
        final nameFromDomain = ptr.domainName
            .replaceAll('.$_domain', '')
            .replaceAll(
                srv.target.replaceAll('.local', '').replaceAll('-', ''), '')
            .replaceAll('-', ' ')
            .trim();

        await for (final ipAddress in client.lookup<IPAddressResourceRecord>(
          ResourceRecordQuery.addressIPv4(srv.target),
        )) {
          host = ipAddress.address.address;
        }

        if (host == srv.target) {
          await for (final ipAddress in client.lookup<IPAddressResourceRecord>(
            ResourceRecordQuery.addressIPv6(srv.target),
          )) {
            host = ipAddress.address.address;
          }
        }

        await for (final text in client.lookup<TxtResourceRecord>(
          ResourceRecordQuery.text(ptr.domainName),
        )) {
          extras = text.text.split('\n').fold<Map<String, String>>(
            <String, String>{},
            (acc, line) {
              final values = line.split('=');
              if (values.length < 2) return acc;
              acc[values.first] = values.skip(1).join('');
              return acc;
            },
          );

          if (extras?['fn']?.isNotEmpty ?? false) {
            nameFromExtras = extras?['fn'];
          } else if (extras?['md']?.isNotEmpty ?? false) {
            nameFromExtras = extras?['md'];
          }
        }

        final device = CastDevice(
          serviceName: serviceName,
          name: nameFromExtras ?? nameFromDomain,
          host: host,
          port: port,
          extras: extras ?? {},
        );

        results.add(device);
      }
    }

    return results.toSet().toList();
  }

  Future<void> stop() async {
    try {
      await _client?.stop();
    } catch (_) {}
    _client = null;
  }
}
