import 'package:flutter/material.dart';

import '../../common.dart';
import '../../private_remote.dart';
import '../tailscale_destination.dart';

class PrivateHomePage extends StatefulWidget {
  final VoidCallback? onSecuritySettings;

  const PrivateHomePage({Key? key, this.onSecuritySettings}) : super(key: key);

  @override
  State<PrivateHomePage> createState() => _PrivateHomePageState();
}

class _PrivateHomePageState extends State<PrivateHomePage> {
  final _address = TextEditingController();
  String? _error;

  @override
  void dispose() {
    _address.dispose();
    super.dispose();
  }

  void _connect() {
    String destination;
    try {
      destination = tailscaleDestination(_address.text);
    } on FormatException catch (error) {
      setState(() => _error = error.message);
      return;
    }
    setState(() => _error = null);
    connect(context, destination);
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      body: SafeArea(
        child: Center(
          child: ConstrainedBox(
            constraints: const BoxConstraints(maxWidth: 640),
            child: ListView(
              shrinkWrap: true,
              padding: const EdgeInsets.all(24),
              children: [
                Text(privateAppDisplayName,
                    style: Theme.of(context).textTheme.headlineMedium),
                const SizedBox(height: 12),
                Text(isPrivateHost ? 'Ev bilgisayarı' : 'Kontrol cihazı',
                    style: Theme.of(context).textTheme.titleLarge),
                const SizedBox(height: 16),
                if (isPrivateHost) ...[
                  const Text(
                    'Gelen erişim için önce en az 20 karakterli, benzersiz kalıcı parola belirleyin ve RustDesk 2FA doğrulamasını tamamlayın. '
                    'Parolayı parola yöneticinizde, 2FA kodlarını ayrı bir doğrulayıcıda tutun. '
                    'Kurulum tamamlanmadan bağlantı kabul edilmez; bu ekran hazır veya güvenli olduğuna dair bir onay değildir.',
                  ),
                  const SizedBox(height: 16),
                  ElevatedButton.icon(
                    onPressed: widget.onSecuritySettings,
                    icon: const Icon(Icons.security),
                    label: const Text('Parola ve 2FA güvenlik ayarları'),
                  ),
                  const SizedBox(height: 24),
                ],
                const Text(
                  'Her iki cihazda da Tailscale açık ve aynı özel ağa bağlı olmalı. '
                  'Tailscale hesabında MFA kullanın ve ağ politikasında yalnızca yetkili kontrol cihazlarından ev bilgisayarının TCP 21118 portuna izin verin. '
                  'İş cihazında yalnızca kurumunuzun izniyle kullanın.',
                ),
                const SizedBox(height: 24),
                if (!isPrivateHost) ...[
                TextField(
                  controller: _address,
                  autocorrect: false,
                  enableSuggestions: false,
                  keyboardType: TextInputType.url,
                  textInputAction: TextInputAction.go,
                  onSubmitted: (_) => _connect(),
                  decoration: InputDecoration(
                    labelText: 'Uzak bilgisayarın Tailscale IP adresi',
                    helperText: '100.64.0.0/10 veya fd7a:115c:a1e0::/48 · TCP 21118',
                    helperMaxLines: 2,
                    errorText: _error,
                    errorMaxLines: 4,
                    border: const OutlineInputBorder(),
                  ),
                ),
                const SizedBox(height: 16),
                ElevatedButton.icon(
                  onPressed: _connect,
                  icon: const Icon(Icons.desktop_windows),
                  label: const Text('Bağlan'),
                ),
                const SizedBox(height: 16),
                ],
                const Text(
                  'Bağlantıda ev bilgisayarının kalıcı parolası ve 2FA kodu sorulur. '
                  'Genel kimlik, sunucu, hesap veya aktarıcı bağlantısı kullanılmaz. '
                  'Kontrol sürümü gelen ekran kontrolünü kabul etmez. '
                  'HarmonyOS cihazında Android APK uyumluluğu ayrıca denenmelidir.',
                ),
                const SizedBox(height: 32),
                const Text(
                  'RustDesk tabanlı kişisel çatallama · AGPL-3.0. '
                  'RustDesk ve katkıda bulunanların telif ve lisans hakları korunur. '
                  'Kaynak kod ve lisans, uygulamanın GitHub dağıtımıyla birlikte sunulur.',
                  style: TextStyle(fontSize: 12),
                ),
              ],
            ),
          ),
        ),
      ),
    );
  }
}
