# eidas-cert-auth

Paquete PHP 8.2+ para autenticar clientes mediante certificados y listas de confianza eIDAS firmadas. El núcleo no depende de Laravel; el adaptador opcional está en `src/Laravel/`.

[English](README.md) · [Seguridad](SECURITY.md) · [Cambios](CHANGELOG.md)

## Instalación y listas de confianza

Requiere PHP 8.2+, extensiones `curl`, `dom`, `libxml`, `openssl` y el ejecutable `openssl` para RSA-PSS y OCSP/CRL. En este checkout: `composer install`. Una vez publicado: `composer require iberfacil/eidas-cert-auth`.

La fuente por defecto es la [LOTL europea](https://ec.europa.eu/tools/lotl/eu-lotl.xml). Se comprueba su firma XMLDSig con las seis huellas SHA-256 del [Diario Oficial C/2026/1944, de 15 de abril de 2026](https://eur-lex.europa.eu/eli/C/2026/1944/oj/eng), configuradas en `Options::OJ_FINGERPRINTS`. Después se sigue únicamente cada puntero XML a una TSL de un país aceptado y se verifica que la firma usa un certificado anunciado en la LOTL. Los cambios futuros de certificados de la LOTL requieren revisar el [mecanismo de pivote](https://ec.europa.eu/tools/lotl/pivot-lotl-explanation.html) y actualizar las huellas de forma controlada: el paquete no sigue pivotes automáticamente.

Por defecto solo se acepta el país de `region` (`ES`); configure `countries` para ampliar la selección. Se importan por defecto certificados CA de servicios `CA/QC` con estado `granted` e indicación `ForeSignatures`, considerando el historial de estados. Los calificadores ETSI `NotQualified` y `QCForLegalPerson` describen los certificados que cumplen sus criterios; no excluyen el servicio CA completo. La validación aplica los criterios de uso de clave y política de certificado al certificado cliente; los criterios no admitidos fallan en cerrado para esa CA. Se crea un PEM por huella, `bundle.pem` y `manifest.json`.

```bash
mkdir -p /path/to/private-data
vendor/bin/eidas-cert-auth trust-list:update --store=/path/to/private-data/trust --region=ES --dry-run
vendor/bin/eidas-cert-auth trust-list:update --store=/path/to/private-data/trust --region=ES
vendor/bin/eidas-cert-auth doctor --store=/path/to/private-data/trust
```

La ruta activa es un enlace simbólico que se sustituye atómicamente por una nueva generación; su carpeta padre debe existir y ser escribible. Se rechaza una lista con menos del 80 % de CAs anteriores en cualquier país, salvo `--force`. Esta opción **solo** omite ese umbral; no acepta firmas erróneas ni listas vacías. `--dry-run` verifica y muestra altas y bajas sin modificar el almacén, aunque el umbral vaya a rechazar el cambio. Se conservan generaciones antiguas para poder revertir; establezca una política de limpieza. La generación se crea con modo 0700: actualice con el mismo usuario que valida, o conceda acceso mediante permisos de despliegue. El validador rechaza un almacén vencido por NextUpdate o sin actualizar durante 30 días por defecto. El almacén conserva el mayor número de secuencia observado por país y por la LOTL, incluso si se retira temporalmente un país. Los almacenes de versiones anteriores necesitan una actualización correcta para incorporar metadatos de caducidad y secuencia antes de volver a validar.

La TSL suelta se importa con `TrustListImporter::importTsl($xml, 'ES', $huellasFirmantes)`. Obtenga esas huellas de una LOTL previamente verificada o de otra publicación de confianza, nunca del propio XML sin verificar. `robrichards/xmlseclibs` (versión 3.1.5 o superior de esa rama) realiza las operaciones XMLDSig; el paquete comprueba además las referencias, algoritmos, transformaciones, raíz firmada y huellas permitidas. Las firmas RSA-PSS, presentes en la TSL alemana actual, se comprueban con OpenSSL. Se verifican también las referencias XAdES presentes en la LOTL actual.

## Validación e identidad

`CertificateValidator::validate()` devuelve `ValidationResult` con `valid`, `reason`, `identity`, `certificate` y `revocationSource`. Se comprueban cadena y firmas hasta el almacén, fechas, carácter de CA de los emisores, keyUsage de firma digital, EKU de autenticación cliente, declaración ETSI QcCompliance (por defecto), país, identificador personal y revocación. Se consulta OCSP primero y CRL si OCSP no sirve; OpenSSL verifica la respuesta o CRL contra el emisor. Hay tiempo límite y caché por huella SHA-256. La falta de respuesta de revocación rechaza por defecto; `softFailRevocation` es una decisión explícita del integrador.

Los extractores ES, PT, IT, FR y DE, más uno genérico ETSI EN 319 412-1, devuelven nombre, apellidos, identificador, país, tipo de persona, organización y representación. Interpretan los prefijos `IDC`, `PAS`, `TIN` y `VAT`; el extractor español maneja además `IDCES-`, `VATES-` y el identificador de una persona representante en el nombre común. Los datos son declaraciones del certificado; el sistema integrador debe vincular usuarios por `(scheme, country, value)` y comprobar el tipo de persona, no solo el valor.

```php
use Iberfacil\EidasCertAuth\Options;
use Iberfacil\EidasCertAuth\Transport\CurlTransport;
use Iberfacil\EidasCertAuth\Trust\{TrustListImporter, TrustStore, XmlSignatureVerifier};

$options = new Options(region: 'ES', countries: ['ES', 'PT']);
$store = new TrustStore('/path/to/private-data/trust', $options->minimumRetentionPercent);
$importer = new TrustListImporter(new CurlTransport(), new XmlSignatureVerifier(), $store, $options);
$preview = $importer->importLotl(dryRun: true);
```

Para construir el validador sin Laravel, consulte el ejemplo completo del [README en inglés](README.md#client-validation-and-identity). `FakeTransport` permite pruebas sin red.

## Terminación TLS con `optional_no_ca`

La opción `ssl_verify_client optional_no_ca` de nginx o `SSLVerifyClient optional_no_ca` de Apache deja presentar certificados de distintas autoridades eIDAS y traslada la decisión de autenticación a PHP. **Esa opción por sí sola no autentica.** Proteja todas las rutas pertinentes con el middleware o una validación equivalente, aísle el origen PHP de los clientes y transmita el certificado mediante una variable de servidor que no pueda crear una cabecera HTTP del navegador. Véanse las directivas oficiales de [nginx](https://nginx.org/en/docs/http/ngx_http_ssl_module.html) y [Apache](https://httpd.apache.org/docs/2.4/mod/mod_ssl.html).

nginx + PHP-FPM, en la ubicación protegida:

```nginx
ssl_verify_client optional_no_ca;
ssl_client_certificate /path/to/private-data/trust/bundle.pem;

location /certificate-login {
    include fastcgi_params;
    fastcgi_param SSL_CLIENT_CERT $ssl_client_escaped_cert;
    fastcgi_param SCRIPT_FILENAME /path/to/public/index.php;
    fastcgi_pass php_backend;
}
```

`$ssl_client_escaped_cert` llega codificado como URL; `CertificateParser` lo normaliza. El ejemplo presupone certificado TLS de servidor, upstream PHP y controles de acceso configurados aparte.

Apache 2.4 + mod_ssl + mod_php:

```apache
SSLVerifyClient optional_no_ca
SSLCACertificateFile /path/to/private-data/trust/bundle.pem
SSLOptions +StdEnvVars +ExportCertData
<Location "/certificate-login">
    Require all granted
</Location>
```

Con PHP-FPM hay que configurar y comprobar la transferencia explícita de la variable de entorno en Apache/FastCGI. Nunca copie `HTTP_SSL_CLIENT_CERT` ni `X-SSL-Client-Cert` desde el navegador a `SSL_CLIENT_CERT`.

## Laravel

El proveedor se descubre automáticamente. Publique la configuración con `php artisan vendor:publish --tag=eidas-cert-auth-config`. Variables habituales: `EIDAS_STORE_PATH`, `EIDAS_REGION`, `EIDAS_COUNTRIES` (separados por comas). La configuración permite tipos de servicio, huellas de firmantes, umbral de sustitución y política de revocación, incluidos `revocation_cache_store`, `intermediates` y `maximum_store_age_seconds`. Laravel usa su caché para los resultados de revocación. `schedule_daily=true` programa el comando a diario por defecto; póngalo a `false` si la aplicación programa las actualizaciones por su cuenta. La aplicación necesita activar su disparador habitual del scheduler.

```bash
php artisan eidas:trust-list:update --dry-run
php artisan eidas:trust-list:update --force
php artisan eidas:doctor
```

Aplique `Iberfacil\EidasCertAuth\Laravel\Middleware\ValidateClientCertificate` a la ruta. Lee `SSL_CLIENT_CERT` de las variables del servidor por defecto. Solo lee una cabecera si se han configurado **a la vez** `trusted_proxy_header` y una lista exacta `trusted_proxy_ips`; compara `REMOTE_ADDR`, no la IP reenviada. El proxy debe borrar cualquier cabecera entrante del mismo nombre y fijar una propia ya verificada. La identidad y el resultado quedan en los atributos `eidas.identity` y `eidas.validation`. Eventos: `TrustListUpdated` y `TrustListRejected`. La fachada `EidasCertAuth` resuelve el validador.

## Desarrollo

```bash
composer install
vendor/bin/phpunit
vendor/bin/phpstan analyse --memory-limit=512M
vendor/bin/pint --test
```

Las pruebas generan durante su ejecución la PKI, las LOTL/TSL firmadas y las respuestas OCSP; no consultan la red. Consulte [CONTRIBUTING.md](CONTRIBUTING.md), [SECURITY.md](SECURITY.md) y [AGENTS.md](AGENTS.md).

MIT © 2026 colaboradores de Iberfacil. Véase [LICENSE](LICENSE).
