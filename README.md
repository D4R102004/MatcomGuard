# **Informe Técnico: MatCom Guard**  

## **Descripción General**  
**MatCom Guard** es un sistema de seguridad diseñado para proteger máquinas virtuales basadas en UNIX mediante la monitorización en tiempo real de dispositivos conectados, procesos del sistema y puertos de red. Su objetivo es detectar y alertar sobre actividades sospechosas, como intrusiones, malware o uso anómalo de recursos.  

El sistema está desarrollado principalmente en **C**, aprovechando su eficiencia en interacción con el kernel de UNIX, y utiliza **scripts de Bash** para automatizar procesos como la compilación y el arranque del sistema. Además, incorpora bibliotecas como **GTK** para proporcionar una interfaz gráfica de usuario (GUI) intuitiva.  

![Diagrama de MatCom Guard](/Readmeimage.png)  
*Figura 1: Sistema MatComGuard*

## **Funcionalidades**  

### **1. Detección y Escaneo de Dispositivos Conectados (USB)**  
#### **Propósito**  
Monitorear dispositivos USB montados para identificar cambios sospechosos en archivos.  

#### **Funcionalidades Clave**  
- Monitoreo recursivo del sistema de archivos en dispositivos USB  
- Comparación con un baseline inicial (hash SHA-256)  
- Alertas en tiempo real para:  
  - Crecimiento inusual de archivos  
  - Replicación de archivos con nombres aleatorios  
  - Cambios en permisos o metadatos  

#### **Interfaz de Usuario**  
Monitoreo automático de dispositivos USB con detección de nuevos dispositivos.  

---  

### **2. Monitoreo de Uso de Recursos (CPU y RAM)**  
#### **Propósito**  
Detectar procesos que consumen recursos excesivos.  

#### **Funcionalidades Clave**  
- Lectura de datos desde `/proc`  
- Alertas para:  
  - Procesos >70% CPU por >10 segundos  
  - Procesos >50% RAM  
- Excepciones para procesos en lista blanca  

#### **Interfaz de Usuario**  
Visualización en tiempo real de procesos con destacado de anomalías.  

---  

### **3. Escaneo de Puertos Locales**  
#### **Propósito**  
Identificar puertos abiertos potencialmente vulnerables.  

#### **Funcionalidades Clave**  
- Escaneo de rangos configurables  
- Detección basada en conexión TCP  
- Alertas para puertos sospechosos  

#### **Interfaz de Usuario**  
Opciones de escaneo manual (rango específico) o automático (puertos comunes).  

---  

### **4. Monitoreo Recursivo de Rutas Personalizadas**  
#### **Propósito**  
Monitorear cambios en directorios específicos.  

#### **Funcionalidades Clave**  
- Análisis de rutas introducidas por el usuario  
- Mismas capacidades de detección que en USB  
- Alertas en tiempo real  

## **Conclusión**  
**MatCom Guard** ofrece una solución integral de seguridad que combina:  
- Monitorización de dispositivos USB  
- Control de procesos en tiempo real  
- Escaneo proactivo de puertos  
- Protección personalizada de directorios  

Su implementación en C con soporte de Bash y GTK proporciona un balance óptimo entre eficiencia del sistema y usabilidad.
