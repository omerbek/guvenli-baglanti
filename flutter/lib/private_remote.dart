import 'dart:io';

const privateRemoteRole =
    String.fromEnvironment('PRIVATE_REMOTE_ROLE', defaultValue: 'controller');

bool get isPrivateHost => Platform.isWindows && privateRemoteRole == 'host';

const privateAppDisplayName = 'Güvenli Bağlantı';
