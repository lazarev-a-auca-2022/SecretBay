Проект: Серверное приложение для автоматической настройки удаленных серверов VPN.
Цель: Создать серверное приложение, которое:

    Принимает запросы от клиентских приложений с данными для удаленного сервера.
    Выполняет автоматическую настройку VPN на удаленном сервере c Ubuntu.
    Обеспечивает безопасность конфигурации удаленного сервера.
    Возвращает клиенту готовую VPN-конфигурацию для OpenVPN и iOS VPN 
    Удаляет все данные клиента после завершения настройки. // меняет пароль?

1. Функциональные требования
1.1. Запрос от клиента

Сервер должен принимать запросы с JSON-данными:

    server_ip (строка): IP-адрес удаленного сервера.
    username (строка): Имя пользователя для входа. // по умолчанию -- root
    auth_method (строка): Метод аутентификации (password или key).
    auth_credential (строка): Пароль или SSH-ключ.
    vpn_type (строка): Тип VPN (iOS vpn или openvpn).

1.2. Настройка удаленного сервера

После получения данных сервер должен:

    Подключиться к удаленному серверу через SSH.
    Установить необходимое ПО для VPN:
        Для OpenVPN: openvpn, easyrsa.
        Для iOS native VPN --  StrongSwan
    Настроить VPN:
        Сгенерировать ключи и конфигурации.
        Включить маршрутизацию трафика.
        Отключить хранение логов.
    Настроить безопасность:
        Установить fail2ban для защиты от атак.
        Отключить ненужные службы и процессы.
        Поменять root пароль пользователя.

1.3. Возврат данных клиенту

Сервер должен вернуть клиенту:

    Конфигурационный файл VPN для подключения (в формате VPN для iPhone (формат .mobileconfig)  или .ovpn для OpenVPN ) и новый пароль удаленного сервера.

1.4. Удаление данных

После выполнения всех операций сервер должен:

    Удалить временные данные, используемые для настройки.
    Удалить информацию о клиенте (например, IP, SSH-ключи) с сервера.

2. Нефункциональные требования
2.1. Производительность

    Сервер должен обрабатывать до 50 запросов одновременно.
    Максимальное время обработки запроса: 120 секунд
    Сервер должен сообщать клиенту о прогрессе выполнения.

2.2. Безопасность

    Все коммуникации с API должны быть защищены через HTTPS.
    Аутентификация клиентов через токены (например, JWT). — тут не уверен
    Изоляция выполнения задач для разных клиентов.

2.3. Надежность

    В случае ошибки выполнение должно быть прервано, а клиенту возвращено соответствующее сообщение.
    Логи ошибок должны записываться на сервере.

2.4. Масштабируемость

    Возможность разворачивания приложения в контейнере Docker для простого масштабирования.


    Язык программирования: Go (Golang).
    Библиотеки:
        Для HTTP: net/http или gorilla/mux.
        Для SSH: golang.org/x/crypto/ssh.
    VPN-сервисы: StrongSwan (IKEv2).
    Контейнеризация: Docker.
    ОС сервера: Ubuntu 22.

Принцип  разработки, написания, форматирования и комментирования код должен соответствовать гайдлайнам гугла https://google.github.io/styleguide/go/
Требования к документированию кода по Google Style Guide:

    Пакеты: Начинайте каждый пакет с комментарием, описывающим его назначение.
    Функции: Документируйте экспортируемые функции. Комментарии начинаются с имени функции и кратко описывают её поведение.
    Типы: Добавляйте комментарии к экспортируемым структурам и интерфейсам, описывая их назначение.
    Переменные и константы: Все экспортируемые переменные и константы должны быть документированы.
    Методы: Документируйте экспортируемые методы. Указывайте, к какому типу они относятся.
    Сложный код: Добавляйте поясняющие комментарии для сложных участков кода.
    Стиль: Используйте однострочные комментарии // и пишите в третьем лице.
    Ясность: Комментарии объясняют, зачем что-то делается, а не как.
    Язык используйте Английский язык.


Результаты работы

    Серверное приложение с поддержкой:
        Настройки IKEv2 VPN.
        Генерации конфигурации для iPhone (.mobileconfig).
        Генерации конфигурации для OpenVPN (.ovn)
        Удаления всех данных клиента после завершения работы и передача нового пароля клиенту.
    Документация:
        Инструкция по развертыванию сервера.
        Примеры запросов к API.
    Тестовый сервер для проверки работы.


