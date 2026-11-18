import 'package:flutter_hbb/common/tailscale_destination.dart';
import 'package:flutter_test/flutter_test.dart';

void main() {
  test('Tailscale IPv4 boundaries use only the fixed direct port', () {
    expect(tailscaleDestination(' 100.64.0.1 '), '100.64.0.1:21118');
    expect(tailscaleDestination('100.127.255.254:21118'),
        '100.127.255.254:21118');
    for (final value in ['100.63.255.254', '100.128.0.1', '192.168.1.1']) {
      expect(() => tailscaleDestination(value), throwsFormatException);
    }
  });

  test('Tailscale IPv6 literals use brackets with the fixed direct port', () {
    expect(tailscaleDestination('fd7a:115c:a1e0::1'),
        '[fd7a:115c:a1e0::1]:21118');
    expect(tailscaleDestination('[fd7a:115c:a1e0::1]:21118'),
        '[fd7a:115c:a1e0::1]:21118');
    expect(() => tailscaleDestination('fd7a:115c:a1e1::1'),
        throwsFormatException);
  });

  test('names, public IDs, alternate ports and URL options are rejected', () {
    for (final value in [
      '',
      '123456789',
      'home.example.com',
      '100.64.0.1:21119',
      '100.64.0.1:',
      '[fd7a:115c:a1e0::1]:443',
      '[fd7a:115c:a1e0::1',
      'fd7a:115c:a1e0::1%tailnet',
      '100.64.0.1/r',
      '100.64.0.1?relay=true',
    ]) {
      expect(() => tailscaleDestination(value), throwsFormatException,
          reason: value);
    }
  });
}
