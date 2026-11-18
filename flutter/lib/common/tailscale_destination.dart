import 'dart:io';

const privateRemotePort = 21118;

String tailscaleDestination(String input) {
  final value = input.trim();
  if (value.isEmpty) {
    throw const FormatException('Ev bilgisayarının Tailscale IP adresini girin.');
  }
  String host = value;
  String? port;
  if (value.startsWith('[')) {
    final end = value.indexOf(']');
    if (end < 0) {
      throw const FormatException('IPv6 adresinin köşeli parantezlerini kontrol edin.');
    }
    host = value.substring(1, end);
    final suffix = value.substring(end + 1);
    if (suffix.isNotEmpty) {
      if (!suffix.startsWith(':')) {
        throw const FormatException('Yalnızca Tailscale IP adresi ve TCP 21118 kullanılabilir.');
      }
      port = suffix.substring(1);
    }
  } else if (value.contains('.') && value.indexOf(':') == value.lastIndexOf(':') && value.contains(':')) {
    final separator = value.indexOf(':');
    host = value.substring(0, separator);
    port = value.substring(separator + 1);
  }
  if (port != null && port != '$privateRemotePort') {
    throw const FormatException('Yalnızca TCP 21118 portuna bağlanılabilir.');
  }
  final address = InternetAddress.tryParse(host);
  if (address == null || host.contains('%')) {
    throw const FormatException('DNS adı veya RustDesk kimliği değil, gerçek bir Tailscale IP adresi girin.');
  }
  final bytes = address.rawAddress;
  final isV4 = address.type == InternetAddressType.IPv4;
  final allowed = isV4
      ? bytes[0] == 100 && bytes[1] >= 64 && bytes[1] <= 127
      : bytes[0] == 0xfd && bytes[1] == 0x7a &&
          bytes[2] == 0x11 && bytes[3] == 0x5c &&
          bytes[4] == 0xa1 && bytes[5] == 0xe0;
  if (!allowed) {
    throw const FormatException('Adres Tailscale ağına ait olmalı: 100.64.0.0/10 veya fd7a:115c:a1e0::/48.');
  }
  return isV4
      ? '${address.address}:$privateRemotePort'
      : '[${address.address}]:$privateRemotePort';
}
