# eu-eidas-cert-auth

[![CI](https://github.com/marxgavilan/eu-eidas-cert-auth/actions/workflows/ci.yml/badge.svg)](https://github.com/marxgavilan/eu-eidas-cert-auth/actions/workflows/ci.yml) [![Packagist](https://img.shields.io/packagist/v/iberfacil/eidas-cert-auth.svg)](https://packagist.org/packages/iberfacil/eidas-cert-auth) [![PHP](https://img.shields.io/packagist/php-v/iberfacil/eidas-cert-auth.svg)](https://packagist.org/packages/iberfacil/eidas-cert-auth) [![Licencia MIT](https://img.shields.io/badge/licencia-MIT-blue.svg)](LICENSE)

Permite que la gente entre en tu web o aplicación con su certificado digital —FNMT, DNIe o de cualquier prestador cualificado de la UE— comprobando de verdad que es válido, procede de una autoridad de confianza oficial y no está revocado. Sin framework, con línea de comandos y adaptador opcional para Laravel.

[English version](README.en.md)

Creado por Marco Gavilán, de IBERFÁCIL.

---

## Para qué sirve (si no eres técnico)

Las contraseñas se olvidan, se reutilizan y se pueden robar. Cuando una gestoría, un despacho o una administración abre un área privada, necesita saber quién entra: si es un cliente, una persona que actúa en nombre de una empresa o alguien que intenta suplantarlos. Pedir un nombre y un NIF escritos en un formulario no demuestra esa identidad.

Este paquete permite usar el certificado digital que la persona presenta al conectarse. La aplicación puede:

1. Consultar la **lista oficial de confianza de la UE**, firmada, para saber qué autoridades y prestadores se aceptan.
2. Comprobar que el certificado está vigente, que su cadena llega a una autoridad admitida y que sirve para la operación solicitada.
3. Consultar si está **revocado**; si no puede comprobarlo, rechaza el acceso por defecto.
4. Extraer los datos declarados en el certificado, como nombre, NIF o identificador equivalente, y, cuando consta, la representación de una empresa. Tu aplicación decide a qué cuenta corresponde esa identidad.

| Qué ves en tu aplicación | Qué significa en la práctica |
| --- | --- |
| **Válido** (`valid: true`) | El certificado supera las comprobaciones del perfil elegido y la identidad se puede asociar a una cuenta según las reglas de tu aplicación. |
| **Caducado o aún no válido** (`expired`, `not_yet_valid`) | Está fuera de su periodo de vigencia. |
| **Revocado** (`revoked`) | El emisor lo ha anulado: no debe dar acceso. |
| **No se pudo comprobar la revocación** (`revocation_unavailable`) | No hay respuesta fiable de OCSP o CRL; se rechaza por defecto y conviene reintentar cuando vuelva el servicio. |
| **Autoridad no admitida o certificado inadecuado** (`untrusted`, `no_authentication_usage`) | La cadena no llega a la lista aceptada, o el certificado no declara el uso requerido. |
| **No cumple las reglas de esta operación** (`country_not_accepted`, `qualified_required`, `dnie_disabled_for_profile`, `authentication_policy_mismatch`, `person_type_not_allowed`) | El perfil pide un país, tipo de persona, política o cualificación que este certificado no cumple. |
| **No se puede identificar a la persona** (`no_personal_identity`, `malformed`) | Falta un identificador utilizable o el certificado no se puede leer. |

Ejemplos de uso reales:

- Una gestoría deja entrar a sus clientes en un área privada sin depender de una contraseña compartida por correo.
- Un despacho distingue entre la persona física y quien se presenta como representante de una empresa antes de abrir un expediente.
- Una administración identifica al solicitante de un trámite y exige un perfil más estricto para operaciones sensibles.
- Un servicio de alta de clientes comprueba el certificado antes de asociar una identidad a una cuenta.
- Una aplicación reserva el flujo de firma a certificados que cumplan el perfil cualificado configurado.

**Qué necesitas:** configurar el servidor web para solicitar el certificado del visitante, mantener actualizado un almacén privado de listas de confianza y proteger las rutas con la validación. El paquete valida certificados; tu aplicación sigue decidiendo permisos y si una representación declarada basta para el trámite concreto. No ejecuta una firma electrónica por sí mismo.

---

## Para desarrolladores

### Requisitos e instalación

Requiere PHP 8.2+, extensiones `curl`, `dom`, `libxml`, `openssl` y el ejecutable `openssl` para RSA-PSS y OCSP/CRL. El núcleo no depende de Laravel; el adaptador opcional está en `src/Laravel/`.

```bash
composer require iberfacil/eidas-cert-auth
```

En este checkout, use `composer install`.

### Listas de confianza y CLI

La fuente por defecto es la [LOTL europea](https://ec.europa.eu/tools/lotl/eu-lotl.xml). Se comprueba su firma XMLDSig con las seis huellas SHA-256 del [Diario Oficial C/2026/1944, de 15 de abril de 2026](https://eur-lex.europa.eu/eli/C/2026/1944/oj/eng), configuradas en `Options::OJ_FINGERPRINTS`. Después se sigue únicamente cada puntero XML a una TSL de un país aceptado y se verifica que la firma usa un certificado anunciado en la LOTL. Los cambios futuros de certificados de la LOTL requieren revisar el [mecanismo de pivote](https://ec.europa.eu/tools/lotl/pivot-lotl-explanation.html) y actualizar las huellas de forma controlada: el paquete no sigue pivotes automáticamente.

Por defecto solo se acepta el país de `region` (`ES`); configure `countries` para ampliar la selección. Se importan por defecto certificados CA de servicios `CA/QC` con estado `granted` e indicación `ForeSignatures`, considerando el historial de estados. Los calificadores ETSI `NotQualified` y `QCForLegalPerson` describen los certificados que cumplen sus criterios; no excluyen el servicio CA completo. Un perfil que exige cualificación aplica esos criterios de uso de clave y política al certificado cliente; los criterios no admitidos impiden reconocerlo como cualificado. Se crea un PEM por huella (`<sha256>.pem`), `bundle.pem` con el conjunto actual y `manifest.json` con país, tipo de servicio, fecha de publicación, vencimiento y números de secuencia.

```bash
mkdir -p /path/to/private-data
vendor/bin/eidas-cert-auth trust-list:update --store=/path/to/private-data/trust --region=ES --dry-run
vendor/bin/eidas-cert-auth trust-list:update --store=/path/to/private-data/trust --region=ES
vendor/bin/eidas-cert-auth doctor --store=/path/to/private-data/trust
```

La ruta activa debe estar ausente o ser un enlace simbólico que se sustituye atómicamente por una nueva generación; su carpeta padre debe existir y ser escribible. Se rechaza una lista con menos del 80 % de CAs anteriores en cualquier país, salvo `--force`. Esta opción **solo** omite ese umbral; no acepta firmas erróneas ni listas vacías. `--dry-run` verifica y muestra altas y bajas sin modificar el almacén, aunque el umbral vaya a rechazar el cambio. Se conservan generaciones antiguas para poder revertir; establezca una política de limpieza. La generación se crea con modo 0700: actualice con el mismo usuario que valida, o conceda acceso mediante permisos de despliegue. El validador rechaza un almacén vencido por NextUpdate o sin actualizar durante 30 días por defecto. El almacén conserva el mayor número de secuencia observado por país y por la LOTL, incluso si se retira temporalmente un país. Los almacenes de versiones anteriores necesitan una actualización correcta para incorporar metadatos de caducidad y secuencia antes de volver a validar.

La TSL suelta se importa con `TrustListImporter::importTsl($xml, 'ES', $huellasFirmantes)`. Obtenga esas huellas de una LOTL previamente verificada o de otra publicación de confianza, nunca del propio XML sin verificar. `robrichards/xmlseclibs` (versión 3.1.5 o superior de esa rama) realiza las operaciones XMLDSig; el paquete comprueba además las referencias, algoritmos, transformaciones, raíz firmada y huellas permitidas. Las firmas RSA-PSS, presentes en la TSL alemana actual, se comprueban con OpenSSL. Se verifican también las referencias XAdES presentes en la LOTL actual.

## Validación e identidad

`CertificateValidator::validate()` devuelve `ValidationResult` con `valid`, `reason`, `identity`, `certificate`, `revocationSource` y el `profile` solicitado. Se comprueban cadena y firmas hasta el almacén, fechas, carácter de CA de los emisores, EKU `clientAuth` cuando existe o keyUsage `digitalSignature` si no hay EKU, requisitos del perfil, país, identificador personal y revocación. Se consulta OCSP primero y CRL si OCSP no sirve; OpenSSL verifica la respuesta o CRL contra el emisor. Hay tiempo límite y caché por huella SHA-256. La falta de respuesta de revocación rechaza por defecto; `softFailRevocation` es una decisión explícita del integrador.

Los extractores ES, PT, IT, FR y DE, más uno genérico ETSI EN 319 412-1, devuelven nombre, apellidos, identificador, país, tipo de persona, organización y representación. Interpretan los prefijos `IDC`, `PAS`, `TIN` y `VAT`; el extractor español maneja además `IDCES-`, `VATES-`, un DNI/NIE sin prefijo en `serialNumber` con letra de control válida y el identificador de una persona representante en el nombre común. Los datos son declaraciones del certificado; el sistema integrador debe vincular usuarios por `(scheme, country, value)` y comprobar el tipo de persona, no solo el valor.

```php
use Iberfacil\EidasCertAuth\Options;
use Iberfacil\EidasCertAuth\Transport\CurlTransport;
use Iberfacil\EidasCertAuth\Trust\{TrustListImporter, TrustStore, XmlSignatureVerifier};

$options = new Options(region: 'ES', countries: ['ES', 'PT']);
$store = new TrustStore('/path/to/private-data/trust', $options->minimumRetentionPercent);
$importer = new TrustListImporter(new CurlTransport(), new XmlSignatureVerifier(), $store, $options);
$preview = $importer->importLotl(dryRun: true);
```

Para construir el validador sin Laravel:

```php
use Iberfacil\EidasCertAuth\Cache\InMemoryRevocationCache;
use Iberfacil\EidasCertAuth\Certificate\{CertificateParser, CertificateValidator, RevocationChecker};

$validator = new CertificateValidator(
    new CertificateParser(), $store,
    new RevocationChecker(new CurlTransport(allowHttp: true), new InMemoryRevocationCache()),
    $options,
);
$resultado = $validator->validate($pemDeVariableServidor);
if (! $resultado->valid) {
    // Use $resultado->reason; no registre el PEM ni la identidad por defecto.
}
```

`FakeTransport` permite pruebas sin red. Las URL de revocación y de emisores AIA pueden usar HTTP. El transporte no sigue redirecciones, rechaza respuestas DNS privadas o reservadas, fija la dirección pública resuelta y limita tiempo y tamaño de descarga. Configure también un cortafuegos de salida. Para una caché de revocación compartida, inyecte su propia implementación de `RevocationCache`. Una respuesta OCSP «good» debe tener `thisUpdate` reciente y `nextUpdate`.

### Criterio de autenticación y perfiles

El perfil `default` acepta un certificado cuya cadena verificada llega a un ancla CA/QC aceptada de una TSL firmada con `ForeSignatures`, y declara uso de autenticación: EKU con `clientAuth`, o ausencia de EKU junto con keyUsage `digitalSignature`. No exige QcCompliance ni un OID de política concreto. Esta regla permite el login con certificados como el de autenticación del DNIe; la hoja debe superar también fechas, cadena, país, identidad y revocación.

**Riesgos:** El perfil por defecto acepta certificados no cualificados; la solidez de la comprobación de identidad depende de las prácticas de emisión de cada prestador. Si la TSL incluye una raíz como AC RAIZ DNIE 2, quedan cubiertas todas sus CA subordinadas, incluidas las que emiten certificados no cualificados. La recuperación AIA causa una petición saliente a una URL del certificado cliente antes de confiar en su cadena: limite la salida con `aia_allowed_hosts` y un cortafuegos. Para operaciones de alto riesgo, como firma, altas o poderes, utilice un perfil con `qualified_required` u OID explícitos de política de autenticación.

La [DPC de la Policía, versión 3.2, apartados 7.1.4 y 7.1.6](https://www.dnielectronico.es/PDFs/Politicas_de_certificacion_v3.2.pdf) documenta el OID `2.16.724.1.2.2.2.4`, `digitalSignature`, ausencia de EKU y DNI/NIE sin prefijo en `serialNumber`. El OID es una restricción **opcional** del perfil mediante `authentication_policies`; para ese OID se admite el sufijo documentado de dos componentes de versión. El interruptor `dnie` reconoce el DNIe por el sujeto del ancla TSL verificada que contiene `DNIE`, nunca por texto de la hoja.

Publique la configuración Laravel con `php artisan vendor:publish --tag=eidas-cert-auth-config` y defina `profiles`, o use `EIDAS_PROFILES` con el objeto JSON equivalente en `.env`. Ejemplo de «DNIe solo para login», «firma solo cualificados» y onboarding sin DNIe:

```php
'profiles' => [
    'default' => [
        'countries' => ['ES'], 'qualified_required' => false,
        'person_types' => ['natural', 'representative'], 'dnie' => true,
        'soft_fail_revocation' => false,
    ],
    'login' => [
        'countries' => ['ES'], 'qualified_required' => false,
        'person_types' => ['natural', 'representative'], 'dnie' => true,
        'soft_fail_revocation' => false,
    ],
    'signature' => [
        'countries' => ['ES'], 'qualified_required' => true,
        'person_types' => ['natural', 'representative'], 'dnie' => false,
        'soft_fail_revocation' => false,
    ],
    'onboarding' => [
        'countries' => ['ES', 'PT'], 'qualified_required' => false,
        'person_types' => ['natural', 'representative', 'legal'], 'dnie' => false,
        'soft_fail_revocation' => false,
    ],
],
```

Un perfil cualificado exige QcCompliance y aplica los criterios `NotQualified`/`QCForLegalPerson` de la TSL. `person_types` admite `natural`, `representative` y `legal` (sello de entidad con identificador de organización). También se exige uso de autenticación al sello. Para restringir políticas, añada al perfil `'authentication_policies' => ['ES' => ['2.16.724.1.2.2.2.4']]`; si se omite, no se exige OID. `soft_fail_revocation` vale `false` por defecto. Los campos omitidos heredan los valores globales; `default` existe sin configuración, acepta ES y DNIe y no exige cualificación. Un nombre inexistente lanza `InvalidArgumentException`. Los motivos de rechazo distinguen `no_authentication_usage`, `dnie_disabled_for_profile`, `qualified_required`, `authentication_policy_mismatch` y `person_type_not_allowed`.

```php
// Ruta Laravel con el alias eidas.cert registrado por el proveedor:
Route::post('/firmar', $handler)->middleware('eidas.cert:signature');

// Núcleo sin Laravel o fachada Laravel:
$resultado = $validator->validate($pemDeVariableServidor, profile: 'signature');
```

Si la hoja llega sin `AC DNIE 00x` y su emisor DN o clave de autoridad no está en el almacén, el validador puede descargar solo la primera URL AIA `caIssuers` de la hoja. Acepta la CA descargada únicamente si firma la hoja y está firmada directamente por un ancla TSL actual; no sigue más AIA. El timeout configurable es de 3–5 segundos (`aia_timeout_seconds`, 4 por defecto) y el límite de respuesta es 100 KB. `aia_fetch` se activa por defecto y se puede desactivar globalmente o por perfil; `aia_allowed_hosts` es una lista opcional de nombres exactos. Los aciertos se guardan una hora y los fallos de descarga cinco minutos. Laravel utiliza `aia_cache_store` o su caché predeterminada; en despliegues con varios workers configure una caché compartida. El núcleo admite una caché PSR-16 mediante `aiaCacheStore`. La caché guarda solo el DER de la CA descargada, nunca la hoja del cliente. La descarga no se convierte en ancla. Puede suministrar PEM mediante `new CertificateValidator(..., intermediates: [$issuerPem])` o `intermediates` en Laravel. Actualice los almacenes antiguos desde listas firmadas para registrar `ForeSignatures` antes de aceptar autenticación sin QcCompliance.

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

El proveedor se descubre automáticamente. Publique la configuración con `php artisan vendor:publish --tag=eidas-cert-auth-config`. Variables habituales: `EIDAS_STORE_PATH`, `EIDAS_REGION`, `EIDAS_COUNTRIES` (separados por comas). La configuración permite tipos de servicio, huellas de firmantes, umbral de sustitución y política de revocación, incluidos `profiles`, `authentication_policies`, `revocation_cache_store`, `intermediates` y `maximum_store_age_seconds`. Laravel usa su caché para los resultados de revocación. `schedule_daily=true` programa el comando a diario por defecto; póngalo a `false` si la aplicación programa las actualizaciones por su cuenta. La aplicación necesita activar su disparador habitual del scheduler.

```bash
php artisan eidas:trust-list:update --dry-run
php artisan eidas:trust-list:update
php artisan eidas:doctor
```

Aplique `Iberfacil\EidasCertAuth\Laravel\Middleware\ValidateClientCertificate` a la ruta. Lee `SSL_CLIENT_CERT` de las variables del servidor por defecto. Solo lee una cabecera si se han configurado **a la vez** `trusted_proxy_header` y una lista exacta `trusted_proxy_ips`; compara `REMOTE_ADDR`, no la IP reenviada. El proxy debe borrar cualquier cabecera entrante del mismo nombre y fijar una propia ya verificada. La identidad y el resultado quedan en los atributos `eidas.identity` y `eidas.validation`. Eventos: `TrustListUpdated` y `TrustListRejected`. La fachada `EidasCertAuth` resuelve el validador.

## Seguridad y límites

- Revise con el responsable de la aplicación los países, tipos de servicio, perfiles, huellas de firmantes del Diario Oficial y política de revocación antes de abrir rutas al público. El valor inicial de `region` es `ES`.
- Proteja todas las rutas de autenticación con `ValidateClientCertificate` o una validación equivalente. Restrinja el acceso directo al origen PHP y acepte cabeceras de certificado solo desde un proxy de IP exacta que elimine las enviadas por el cliente.
- Guarde el almacén de confianza en una ruta privada y escribible. Revise las altas y bajas del `--dry-run` antes de publicar una actualización; use `--force` solo tras investigar una caída de recuento.
- No guarde ni registre PEM de certificados, claves privadas, datos de identidad ni respuestas de revocación sin una política de privacidad diseñada para ello. Vincule las cuentas por esquema, país y valor del identificador, y compruebe la representación exigida por cada trámite.

## Desarrollo

```bash
composer install
vendor/bin/phpunit
vendor/bin/phpstan analyse --memory-limit=512M
vendor/bin/pint --test
```

Las pruebas generan durante su ejecución la PKI, las LOTL/TSL firmadas y las respuestas OCSP; no consultan la red. Consulte [CONTRIBUTING.md](CONTRIBUTING.md), [SECURITY.md](SECURITY.md) y [AGENTS.md](AGENTS.md).

## Licencia

MIT. Copyright (c) 2026 Marco Gavilán — IBERFÁCIL. Véase [LICENSE](LICENSE).
