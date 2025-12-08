import 'dart:async';

import 'package:multicast_dns/multicast_dns.dart';

import 'device.dart';

const _domain = '_googlecast._tcp.local';

class CastDiscoveryService {
  static final CastDiscoveryService _instance = CastDiscoveryService._();
  CastDiscoveryService._();

  factory CastDiscoveryService() => _instance;

  MDnsClient? _client;
  bool _isSearching = false;

  Future<List<CastDevice>> search(
      {Duration timeout = const Duration(seconds: 5)}) async {
    if (_isSearching) {
      // Prevent overlapping searches
      return [];
    }

    _isSearching = true;
    final results = <CastDevice>[];

    // Reuse the client instead of creating a new one each time
    _client ??= MDnsClient();

    try {
      await Future.delayed(Duration(seconds: 1));
      await _client!.start(); // Will throw if already started, so wrap in try

      await for (PtrResourceRecord ptr in _client!.lookup<PtrResourceRecord>(
        ResourceRecordQuery.serverPointer(_domain),
        timeout: timeout,
      )) {
        if (results.any((x) => x.serviceName == ptr.domainName)) {
          continue;
        }

        await for (final srv in _client!.lookup<SrvResourceRecord>(
            ResourceRecordQuery.service(ptr.domainName))) {
          final port = srv.port;
          String host = srv.target;
          Map<String, String>? extras;

          await for (final ipAddress in _client!
              .lookup<IPAddressResourceRecord>(
                  ResourceRecordQuery.addressIPv4(srv.target))) {
            host = ipAddress.address.address;
          }

          if (host == srv.target) {
            await for (final ipAddress in _client!
                .lookup<IPAddressResourceRecord>(
                    ResourceRecordQuery.addressIPv6(srv.target))) {
              host = ipAddress.address.address;
            }
          }

          await for (final text in _client!.lookup<TxtResourceRecord>(
              ResourceRecordQuery.text(ptr.domainName))) {
            extras = text.text.split('\n').fold<Map<String, String>>({},
                (acc, line) {
              final values = line.split('=');
              if (values.length < 2) return acc;
              acc[values.first] = values.skip(1).join('');
              return acc;
            });
          }

          final name = extras?['fn'] ??
              extras?['md'] ??
              ptr.domainName
                  .replaceAll('.$_domain', '')
                  .replaceAll('-', ' ')
                  .trim();

          results.add(CastDevice(
            serviceName: ptr.domainName,
            name: name,
            host: host,
            port: port,
            extras: extras ?? {},
          ));
        }
      }
    } catch (e) {
      print("mDNS error sigh: $e");
    } finally {
      _client?.stop(); // Always stop after search
      _client = null; // Ensure clean recreation next time
      _isSearching = false;

      await Future.delayed(const Duration(milliseconds: 200));
    }

    return results.toSet().toList();
  }
}
