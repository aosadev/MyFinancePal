#MyFinancePal

MyFinancePal es una aplicación de gestión de finanzas personales diseñada para ayudarte a llevar un control detallado de tus ingresos, gastos y presupuestos. Con MyFinancePal, puedes registrar transacciones, categorizar tus gastos e ingresos, gestionar transacciones recurrentes y visualizar tus finanzas a través de gráficos y reportes detallados.
Características Principales

    Registro de Transacciones:
        Crear, leer, actualizar y eliminar transacciones.
        Clasificar transacciones como ingresos o gastos.
        Añadir descripciones y fechas a las transacciones.

    Categorías de Transacciones:
        Crear y gestionar diferentes categorías de ingresos y gastos (por ejemplo, sueldo, alquiler, comida, etc.).

    Transacciones Recurrentes:
        Configurar ingresos y gastos recurrentes (diarios, semanales, mensuales, anuales).
        Gestionar la recurrencia y las fechas de las transacciones automáticas.

    Formas de Pago:
        Registrar transacciones utilizando diferentes métodos de pago (tarjeta, transferencia, efectivo, etc.).

    Cuadro de Mando:
        Visualizar un resumen de tus finanzas con gráficos interactivos.
        Consultar el balance general, ingresos totales, gastos totales y las tendencias financieras.

Tecnologías Utilizadas

    Frontend:
        React
        Material-UI
        Axios
        Chart.js y React-Chartjs-2

    Backend:
        Go (Golang)
        SQLite para la base de datos

Instalación
Requisitos Previos

    Node.js y npm
    Go (Golang)
    SQLite

Configuración del Backend

    Clona este repositorio:

    bash

git clone https://github.com/tu-usuario/myfinancepal.git
cd myfinancepal

Navega al directorio del backend y ejecuta el servidor Go:

bash

    cd backend
    go run main.go

Configuración del Frontend

    Navega al directorio del frontend e instala las dependencias:

    bash

cd ../frontend
npm install

Inicia la aplicación React:

bash

    npm start

Uso

    Accede a la aplicación en tu navegador en http://localhost:3000.
    Utiliza el cuadro de mando para obtener una vista general de tus finanzas.
    Navega a la sección de transacciones para agregar, editar o eliminar transacciones.
    Configura transacciones recurrentes para automatizar ingresos y gastos frecuentes.
    Visualiza reportes detallados y gráficos interactivos para analizar tus hábitos financieros.

Contribución

Si deseas contribuir a este proyecto, por favor, sigue los siguientes pasos:

    Haz un fork del repositorio.
    Crea una rama nueva (git checkout -b feature/nueva-funcionalidad).
    Realiza los cambios necesarios y haz commit (git commit -m 'Añadir nueva funcionalidad').
    Sube tus cambios (git push origin feature/nueva-funcionalidad).
    Abre un Pull Request.

Licencia

Este proyecto está licenciado bajo la MIT License.
