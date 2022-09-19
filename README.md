# CI/CD для проекта YAMDb API.

Настройка CI/CD процессов для проекта [API_YaMDb](https://github.com/artemkms/api_yamdb), который собирает отзывы для пользователей на различные произведения.  

![Yamdb_workflow](https://github.com/artemkms/yamdb_final/actions/workflows/yamdb_workflow.yaml/badge.svg)

### Описание
Для проекта настроен полный непрерывный процесс разработки, тестирования и деплоя кода на боевой сервер. В качестве сервиса для построения процессов CI(continue integration) 
and CD(continue development) выбраны сервисы GitHub и GitHub Actions. В качестве основной системы контроля версия Github service.

### Как это работает.
С проектом теперь можно работать в режиме непрерывной разработки, тестирования и деплоя кода на сервер. Для репозитария на GitHub настроен workflow, рабочая область проека на сервисе GitHub Action. В этой области моделируется процесс и все действия, которые нужно произвести над проектом.
Когда происходит push коммита в master ветку репозитария запускается следующая цепочка событий:
- Стадия 1. Тестирование.
  - тест кода на соответствие стандарту PEP8.
  - тесты разработчиков на соответсвие логики проетка. В качествое основного инструмента тестирования используем pytest.
- Cтадия 2. Сборка докер образа проекта из репозитария и отправка его на Docker hub
- Стадия 3. Деплой на "боевой" сервер. Для орекстрации всеми необходимыми контейнерами, используем docker-compose плагин. Плагин настраиваем через yaml файл конфигурации.
- Стадия 4. Отправляется сообщение в телеграмм бот, об успешном деплое на боевой сервер. Дополнительно репозитарий имеет бейдж. Он размещен в файле шапке readme.md и отражает текущий результат сборки workflow. 

### Технологии  
- CI(continue integration)/CD(continue development)
- GitHub
- GitHub Action
- docker
- docke-compose
- Docker hub repo
- yaml configuration file
- Nginx
- gunicorn wsgi server
- postgres sql
- DRF (django rest full API)
- Yandex.Cloud

### Авторы проекта
[Артем Павлищев](https://github.com/artemkms), python-developer
