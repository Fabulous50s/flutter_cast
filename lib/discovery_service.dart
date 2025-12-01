import 'dart:async';
import 'dart:io';

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
    // already started
    if (_client != null) return;

    // someone else is starting → wait
    if (_starting && _startCompleter != null) {
      return _startCompleter!.future;
    }

    _starting = true;
    _startCompleter = Completer<void>();

    final c = MDnsClient();
    try {
      await c.start();
      _client = c;
      _startCompleter!.complete();
    } on SocketException catch (e) {
      // errno 48 = "address already in use"
      if (e.osError?.errorCode == 48) {
        _client = c; // reuse
        _startCompleter!.complete();
      } else {
        _startCompleter!.completeError(e);
        rethrow;
      }
    } finally {
      _starting = false;
    }
  }

  Future<List<CastDevice>> search({
    Duration timeout = const Duration(seconds: 5),
  }) async {
    await _ensureStarted();
    final client = _client!;
    final results = <CastDevice>[];

    await for (final ptr in client.lookup<PtrResourceRecord>(
      ResourceRecordQuery.serverPointer(_domain),
      timeout: timeout,
    )) {
      // prevent duplicates
      if (results.any((x) => x.serviceName == ptr.domainName)) continue;

      await for (final srv in client.lookup<SrvResourceRecord>(
        ResourceRecordQuery.service(ptr.domainName),
      )) {
        final serviceName = ptr.domainName;
        final port = srv.port;
        String host = srv.target;
        Map<String, String>? extras;

        // try useful name from extras, fallback to sanitized domain
        String? nameFromExtras;
        final nameFromDomain = ptr.domainName
            .replaceAll('.$_domain', '')
            .replaceAll(
                srv.target.replaceAll('.local', '').replaceAll('-', ''), '')
            .replaceAll('-', ' ')
            .trim();

        // resolve IPv4
        await for (final ip in client.lookup<IPAddressResourceRecord>(
          ResourceRecordQuery.addressIPv4(srv.target),
        )) {
          host = ip.address.address;
        }

        // maybe IPv6
        if (host == srv.target) {
          await for (final ip in client.lookup<IPAddressResourceRecord>(
            ResourceRecordQuery.addressIPv6(srv.target),
          )) {
            host = ip.address.address;
          }
        }

        // TXT metadata
        await for (final text in client.lookup<TxtResourceRecord>(
          ResourceRecordQuery.text(ptr.domainName),
        )) {
          extras = text.text.split('\n').fold<Map<String, String>>(
            {},
            (acc, line) {
              final parts = line.split('=');
              if (parts.length < 2) return acc;
              acc[parts.first] = parts.skip(1).join('');
              return acc;
            },
          );

          if (extras?['fn']?.isNotEmpty ?? false) {
            nameFromExtras = extras!['fn'];
          } else if (extras?['md']?.isNotEmpty ?? false) {
            nameFromExtras = extras!['md'];
          }
        }

        results.add(
          CastDevice(
            serviceName: serviceName,
            name: nameFromExtras ?? nameFromDomain,
            host: host,
            port: port,
            extras: extras ?? {},
          ),
        );
      }
    }

    // avoid duplicates by converting to set
    return results.toSet().toList();
  }

  Future<void> stop() async {
    try {
      final c = _client;
      if (c != null) {
        await c.stop();
      }
    } catch (_) {}
    _client = null;
  }
}
