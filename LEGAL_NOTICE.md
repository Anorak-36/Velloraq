# Aviso legal

Velloraq es una herramienta defensiva y de solo lectura para evaluar la seguridad de entornos cloud y serverless que sean propios, operados por tu organizacion o auditados con autorizacion explicita.

## Uso defensivo y autorizado

Usa este proyecto solo para revisiones de seguridad legales, auditorias internas, validaciones de cumplimiento, controles de CI/CD y evaluaciones defensivas de postura cloud.

No uses esta herramienta contra sistemas, cuentas cloud, suscripciones, proyectos, aplicaciones, APIs, servicios de almacenamiento o repositorios de terceros salvo que tengas autorizacion explicita. Se recomienda obtener permiso por escrito antes de auditar cualquier entorno que no este exclusivamente bajo tu control.

## Sin explotacion ni acciones destructivas

El proyecto esta diseñado para evitar explotacion activa. No debe usarse para:

- Explotar vulnerabilidades.
- Interrumpir servicios.
- Modificar, borrar, corromper, cifrar o alterar recursos cloud.
- Exfiltrar datos.
- Recopilar, almacenar o publicar secretos, tokens de acceso, credenciales, datos de clientes u otra informacion sensible.
- Evadir autenticacion, autorizacion, limites de uso, logging o monitorizacion.

El modo previsto de operacion es read-only siempre que el proveedor cloud lo permita. Los usuarios deben ejecutar el scanner con credenciales de minimo privilegio y solo lectura.

## Tratamiento de datos sensibles

El scanner intenta minimizar el tratamiento de informacion sensible. Por ejemplo, las variables de entorno se inspeccionan para identificar nombres o patrones sospechosos, pero los reportes deben incluir nombres de variables y no valores secretos. Las evidencias de codigo fuente se redactan parcialmente cuando contienen patrones compatibles con secretos. Aun asi, los usuarios siguen siendo responsables de revisar los reportes antes de compartirlos fuera de su organizacion.

## Sin garantia legal absoluta

Este proyecto puede ayudar a reducir riesgos operativos y legales cuando se usa de forma responsable, pero no garantiza cumplimiento legal. Las leyes y obligaciones contractuales varian por pais, jurisdiccion, sector, contrato cloud, contexto laboral y alcance de autorizacion.

El usuario es el unico responsable de asegurar que el uso del software cumple con leyes, regulaciones, contratos, terminos de proveedores cloud, politicas internas y autorizaciones por escrito aplicables.

## Exclusion de responsabilidad

El software se proporciona "tal cual", sin garantias de ningun tipo. Los autores y contribuidores no son responsables por mal uso, escaneos no autorizados, impacto operativo, exposicion de datos, reclamaciones legales, daños u otras consecuencias derivadas del uso del software.

En caso de duda, consulta con asesoria legal cualificada y obten permiso por escrito antes de ejecutar la herramienta.
