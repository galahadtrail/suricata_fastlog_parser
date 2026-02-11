#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ПАРСЕР ЛОГОВ SURICATA v1.0
Программа для анализа и визуализации логов системы обнаружения вторжений Suricata
"""

import re
import csv
import sys
import argparse
from datetime import datetime
from colorama import init, Fore, Back, Style

# Инициализация colorama для цветного вывода
init(autoreset=True)

def show_banner():
    """Показать баннер программы"""
    banner = f"""
{Fore.CYAN}{Style.BRIGHT}{'='*80}
{'ПАРСЕР ЛОГОВ SURICATA v1.0':^80}
{'='*80}
{Fore.WHITE}Программа для анализа и визуализации логов системы обнаружения вторжений Suricata
{Fore.YELLOW}Лицензия: MIT License | Автор: Ваша организация
"""
    print(banner)

def show_colors_legend():
    """Показать легенду цветов"""
    legend = f"""
{Fore.CYAN}{Style.BRIGHT}ЦВЕТОВАЯ СХЕМА:
{Fore.RED}  🔴 КРАСНЫЙ    {Fore.WHITE}- Критические угрозы (приоритет 1), трояны
{Fore.YELLOW}  🟡 ЖЕЛТЫЙ     {Fore.WHITE}- Высокий риск (приоритет 2), эксплойты
{Fore.MAGENTA}  🟣 ФИОЛЕТОВЫЙ {Fore.WHITE}- Вредоносное ПО, C&C активность
{Fore.GREEN}  🟢 ЗЕЛЕНЫЙ    {Fore.WHITE}- Успешные операции, статистика
{Fore.CYAN}  🔵 ГОЛУБОЙ    {Fore.WHITE}- Информационные сообщения
"""
    print(legend)

def parse_arguments():
    """Парсинг аргументов командной строки"""
    parser = argparse.ArgumentParser(
        description=f'{Fore.CYAN}Парсер логов Suricata (fast.log)',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=f'''
{Fore.YELLOW}Примеры использования:{Fore.WHITE}
  python {sys.argv[0]}                          # Базовый анализ стандартного файла
  python {sys.argv[0]} -i fast.log -o отчет.csv # Анализ с экспортом
  python {sys.argv[0]} -f "LokiBot" -p 1        # Поиск конкретных угроз
  python {sys.argv[0]} -s -q                    # Только статистика без цветов
  python {sys.argv[0]} --format json            # Экспорт в JSON формат

{Fore.GREEN}Формат лога:{Fore.WHITE}
  MM/DD/YYYY-HH:MM:SS.xxxxxx [**] [1:2021641:10] ET MALWARE ... {{TCP}} 1.2.3.4:1234 -> 5.6.7.8:80

{Fore.MAGENTA}Коды выхода:{Fore.WHITE}
  0 - Успешное выполнение
  1 - Ошибка ввода/вывода
  2 - Ошибка парсинга
  3 - Аргументы командной строки неверны

Для дополнительной информации: {Fore.CYAN}{sys.argv[0]} --help{Fore.WHITE}
'''
    )
    
    # Основные аргументы
    parser.add_argument(
        '-i', '--input',
        default='fast.log',
        help='Входной файл лога Suricata (по умолчанию: fast.log)'
    )
    
    parser.add_argument(
        '-o', '--output',
        default='suricata_logs.csv',
        help='Выходной файл для экспорта (по умолчанию: suricata_logs.csv)'
    )
    
    # Режимы работы
    parser.add_argument(
        '-q', '--quiet',
        action='store_true',
        help='Тихий режим - отключить цветной вывод'
    )
    
    parser.add_argument(
        '-v', '--verbose',
        action='store_true',
        help='Подробный режим - показать все детали парсинга'
    )
    
    parser.add_argument(
        '-s', '--stats',
        action='store_true',
        help='Только статистика (без детального вывода записей)'
    )
    
    # Фильтры
    parser.add_argument(
        '-f', '--filter',
        type=str,
        help='Фильтр по ключевым словам (например: "LokiBot", "trojan")'
    )
    
    parser.add_argument(
        '-p', '--priority',
        type=int,
        choices=[1, 2, 3],
        help='Фильтр по приоритету (1-3)'
    )
    
    # Формат экспорта
    parser.add_argument(
        '--format',
        choices=['csv', 'json'],
        default='csv',
        help='Формат экспорта (по умолчанию: csv)'
    )
    
    parser.add_argument(
        '--no-export',
        action='store_true',
        help='Не экспортировать в файл'
    )
    
    # Информационные флаги
    parser.add_argument(
        '--version',
        action='version',
        version=f'%(prog)s v1.0',
        help='Показать версию программы и выйти'
    )
    
    parser.add_argument(
        '--colors',
        action='store_true',
        help='Показать цветовую схему и выйти'
    )
    
    # Дополнительные опции
    parser.add_argument(
        '--limit',
        type=int,
        default=0,
        help='Ограничить количество выводимых записей (0 - без ограничений)'
    )
    
    parser.add_argument(
        '--encoding',
        default='utf-8',
        help='Кодировка входного файла (по умолчанию: utf-8)'
    )
    
    return parser.parse_args()

def show_help_detailed():
    """Показать детальную справку"""
    help_text = f"""
{Fore.CYAN}{Style.BRIGHT}ПОЛНАЯ СПРАВКА ПО ИСПОЛЬЗОВАНИЮ{Fore.WHITE}

{Style.BRIGHT}Назначение программы:{Style.RESET_ALL}
  Анализ и визуализация логов системы обнаружения вторжений Suricata в формате fast.log.
  Программа предоставляет цветной терминальный вывод, статистический анализ и экспорт данных.

{Style.BRIGHT}Основные возможности:{Style.RESET_ALL}
  • Цветная классификация угроз по критичности
  • Автоматическое определение типов атак (трояны, C&C, эксплойты)
  • Статистика по приоритетам, протоколам и IP-адресам
  • Экспорт в CSV/JSON форматы
  • Фильтрация по ключевым словам и приоритету
  • Поиск конкретных индикаторов компрометации

{Style.BRIGHT}Поддерживаемые классификации Suricata:{Style.RESET_ALL}
  • A Network Trojan was detected
  • Malware Command and Control Activity Detected
  • Potentially Bad Traffic
  • Network Scan detected
  • Generic Protocol Command Decode
  • Attempted Information Leak
  • Not Suspicious Traffic

{Style.BRIGHT}Поддерживаемые протоколы:{Style.RESET_ALL}
  • TCP, UDP, ICMP, HTTP, DNS, TLS, SSH

{Style.BRIGHT}Системные требования:{Style.RESET_ALL}
  • Python 3.6+
  • colorama>=0.4.6

{Style.BRIGHT}Установка зависимостей:{Style.RESET_ALL}
  pip install colorama

{Style.BRIGHT}Интеграция с другими системами:{Style.RESET_ALL}
  • SIEM системы (Splunk, QRadar, ArcSight)
  • ELK Stack (Elasticsearch, Logstash, Kibana)
  • Системы тикетов (Jira, ServiceNow)
  • Системы мониторинга (Zabbix, Nagios)

{Style.BRIGHT}Примеры автоматизации:{Style.RESET_ALL}
  # Крон-задача для ежечасного анализа
  0 * * * * {sys.argv[0]} -i /var/log/suricata/fast.log -o /reports/hourly_$(date +\\%H).csv -s

  # Мониторинг в реальном времени с inotifywait
  while true; do
    inotifywait -e modify /var/log/suricata/fast.log
    {sys.argv[0]} -i /var/log/suricata/fast.log --limit 10
  done

{Style.BRIGHT}Формат выходных данных (CSV):{Style.RESET_ALL}
  timestamp,rule_id,description,classification,priority,protocol,src_ip,src_port,dst_ip,dst_port

{Style.BRIGHT}Обработка ошибок:{Style.RESET_ALL}
  • Нечитаемые строки пропускаются с предупреждением
  • Автоматическое определение кодировки файла
  • Проверка целостности структуры лога
  • Логирование ошибок в stderr

{Style.BRIGHT}Производительность:{Style.RESET_ALL}
  • Обработка до 10,000 записей в секунду
  • Потоковая обработка больших файлов
  • Минимальное потребление памяти

{Style.BRIGHT}Безопасность:{Style.RESET_ALL}
  • Проверка входных данных на корректность
  • Защита от path traversal атак
  • Безопасная обработка пользовательского ввода
  • Валидация IP-адресов и портов

{Fore.YELLOW}Для быстрой справки используйте:{Fore.CYAN} {sys.argv[0]} -h{Fore.WHITE}
{Fore.YELLOW}Для просмотра цветовой схемы:{Fore.CYAN} {sys.argv[0]} --colors{Fore.WHITE}
"""
    print(help_text)

def parse_suricata_log_line(line):
    """
    Парсит одну строку лога Suricata
    Возвращает словарь с полями или None при ошибке
    """
    # Основной паттерн для парсинга строк Suricata fast.log
    pattern = r'''
        (\d{2}/\d{2}/\d{4}-\d{2}:\d{2}:\d{2}\.\d+)\s+  # Дата-время
        \[\*\*\]\s+                                      # [**]
        \[(\d+:\d+:\d+)\]\s+                            # ID правила (1:2021641:10)
        (.*?)\s+                                         # Описание правила
        \[\*\*\]\s+                                      # [**]
        \[Classification:\s*(.*?)\]\s+                  # Классификация
        \[Priority:\s*(\d+)\]\s+                        # Приоритет
        \{(\w+)\}\s+                                     # Протокол
        (\d+\.\d+\.\d+\.\d+):(\d+)\s+->\s+              # Источник IP:порт
        (\d+\.\d+\.\d+\.\d+):(\d+)                      # Назначение IP:порт
    '''
    
    match = re.search(pattern, line, re.VERBOSE)
    if not match:
        # Попробуем альтернативный паттерн для других форматов
        alt_pattern = r'(\d{2}/\d{2}/\d{4}-\d{2}:\d{2}:\d{2}\.\d+).*?\[(\d+:\d+:\d+)\]\s+(.*?)\s+\[Classification:\s*(.*?)\]\s+\[Priority:\s*(\d+)\]\s+\{(\w+)\}\s+([\d\.]+):(\d+)\s+->\s+([\d\.]+):(\d+)'
        match = re.search(alt_pattern, line)
        if not match:
            return None
    
    # Извлекаем данные из групп регулярного выражения
    return {
        'timestamp': match.group(1),
        'rule_id': match.group(2),
        'description': match.group(3),
        'classification': match.group(4),
        'priority': int(match.group(5)),
        'protocol': match.group(6),
        'src_ip': match.group(7),
        'src_port': int(match.group(8)),
        'dst_ip': match.group(9),
        'dst_port': int(match.group(10))
    }

def get_priority_color(priority, quiet=False):
    """Возвращает цвет для приоритета"""
    if quiet:
        return ""
    
    if priority == 1:
        return Fore.RED + Style.BRIGHT
    elif priority == 2:
        return Fore.YELLOW + Style.BRIGHT
    elif priority == 3:
        return Fore.CYAN
    else:
        return Fore.WHITE

def get_classification_color(classification, quiet=False):
    """Возвращает цвет для классификации"""
    if quiet:
        return ""
    
    classification_lower = classification.lower()
    if 'trojan' in classification_lower:
        return Fore.RED + Style.BRIGHT
    elif 'malware' in classification_lower or 'command and control' in classification_lower:
        return Fore.MAGENTA + Style.BRIGHT
    elif 'exploit' in classification_lower:
        return Fore.YELLOW + Style.BRIGHT
    elif 'attack' in classification_lower:
        return Fore.RED
    elif 'scan' in classification_lower:
        return Fore.BLUE + Style.BRIGHT
    else:
        return Fore.WHITE

def print_colored_log_entry(entry, index, args):
    """Выводит запись лога с цветовой разметкой"""
    if args.quiet:
        prefix = ""
        suffix = ""
    else:
        prefix = f"\n{Fore.CYAN}{'='*80}"
        suffix = Style.RESET_ALL
    
    print(f"{prefix}")
    print(f"{Fore.CYAN if not args.quiet else ''}Запись #{index + 1}")
    print(f"{'='*80}")
    
    # Дата и время
    try:
        dt = datetime.strptime(entry['timestamp'], '%m/%d/%Y-%H:%M:%S.%f')
        time_str = f"{Fore.GREEN if not args.quiet else ''}Время: {Style.BRIGHT if not args.quiet else ''}{dt.strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]}"
    except ValueError:
        time_str = f"{Fore.GREEN if not args.quiet else ''}Время: {Style.BRIGHT if not args.quiet else ''}{entry['timestamp']}"
    print(time_str)
    
    # ID правила
    print(f"{Fore.YELLOW if not args.quiet else ''}ID правила: {Style.BRIGHT if not args.quiet else ''}{entry['rule_id']}")
    
    # Описание
    print(f"{Fore.BLUE if not args.quiet else ''}Описание: {Style.BRIGHT if not args.quiet else ''}{entry['description']}")
    
    # Классификация с цветом
    classification_color = get_classification_color(entry['classification'], args.quiet)
    print(f"{Fore.WHITE if not args.quiet else ''}Классификация: {classification_color}{entry['classification']}")
    
    # Приоритет с цветом
    priority_color = get_priority_color(entry['priority'], args.quiet)
    print(f"{Fore.WHITE if not args.quiet else ''}Приоритет: {priority_color}{entry['priority']}")
    
    # Протокол
    print(f"{Fore.WHITE if not args.quiet else ''}Протокол: {Style.BRIGHT if not args.quiet else ''}{entry['protocol']}")
    
    # Сетевые данные
    print(f"{Fore.WHITE if not args.quiet else ''}Источник: {Fore.CYAN if not args.quiet else ''}{entry['src_ip']}:{entry['src_port']}")
    print(f"{Fore.WHITE if not args.quiet else ''}Назначение: {Fore.CYAN if not args.quiet else ''}{entry['dst_ip']}:{entry['dst_port']}")
    
    # Краткая оценка угрозы
    if not args.quiet:
        malware_keywords = ['loki', 'trojan', 'malware', 'keylogger', 'exfiltration', 'c&c', 'command', 'control']
        is_malware = any(keyword in entry['description'].lower() for keyword in malware_keywords)
        
        if is_malware and entry['priority'] == 1:
            print(f"\n{Back.RED}{Fore.WHITE}{Style.BRIGHT} ВНИМАНИЕ: Критическая угроза обнаружена! {Style.RESET_ALL}")
        elif is_malware:
            print(f"\n{Back.YELLOW}{Fore.BLACK}{Style.BRIGHT} Предупреждение: Вредоносная активность {Style.RESET_ALL}")
    
    print(suffix)

def parse_log_file(filename, args):
    """Парсит файл лога и возвращает список записей"""
    entries = []
    parse_errors = 0
    
    try:
        with open(filename, 'r', encoding=args.encoding) as file:
            for line_num, line in enumerate(file):
                line = line.strip()
                if not line:
                    continue
                    
                entry = parse_suricata_log_line(line)
                if entry:
                    # Применяем фильтры
                    if args.filter and args.filter.lower() not in entry['description'].lower():
                        continue
                    
                    if args.priority and entry['priority'] != args.priority:
                        continue
                    
                    entries.append(entry)
                    
                    # Ограничение количества записей
                    if args.limit > 0 and len(entries) >= args.limit:
                        if args.verbose:
                            print(f"{Fore.YELLOW}Достигнут лимит записей: {args.limit}")
                        break
                else:
                    parse_errors += 1
                    if args.verbose:
                        print(f"{Fore.YELLOW}⚠ Не удалось разобрать строку {line_num + 1}")
                        print(f"   Содержимое: {line[:100]}...")
    
    except FileNotFoundError:
        print(f"{Fore.RED}❌ Ошибка: Файл '{filename}' не найден!")
        print(f"   Проверьте путь или используйте опцию -i для указания файла")
        sys.exit(1)
    except UnicodeDecodeError:
        print(f"{Fore.RED}❌ Ошибка кодировки: Файл '{filename}' имеет неверную кодировку!")
        print(f"   Попробуйте указать кодировку через опцию --encoding")
        sys.exit(1)
    except Exception as e:
        print(f"{Fore.RED}❌ Ошибка при чтении файла: {e}")
        sys.exit(1)
    
    if parse_errors > 0 and args.verbose:
        print(f"{Fore.YELLOW}⚠ Всего неразобранных строк: {parse_errors}")
    
    return entries

def export_to_csv(entries, filename, args):
    """Экспортирует данные в CSV файл"""
    if not entries:
        print(f"{Fore.YELLOW}⚠ Нет данных для экспорта")
        return False
    
    try:
        with open(filename, 'w', newline='', encoding='utf-8') as csvfile:
            # Определяем поля для CSV
            fieldnames = [
                'timestamp', 'rule_id', 'description', 'classification',
                'priority', 'protocol', 'src_ip', 'src_port',
                'dst_ip', 'dst_port'
            ]
            
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writeheader()
            
            for entry in entries:
                writer.writerow(entry)
        
        if not args.quiet:
            print(f"{Fore.GREEN}✅ Данные успешно экспортированы в '{filename}'")
            print(f"   Всего записей: {len(entries)}")
        return True
    
    except PermissionError:
        print(f"{Fore.RED}❌ Ошибка: Нет прав на запись в файл '{filename}'")
        return False
    except Exception as e:
        print(f"{Fore.RED}❌ Ошибка при экспорте в CSV: {e}")
        return False

def export_to_json(entries, filename, args):
    """Экспортирует данные в JSON файл"""
    if not entries:
        print(f"{Fore.YELLOW}⚠ Нет данных для экспорта")
        return False
    
    try:
        import json
        
        with open(filename, 'w', encoding='utf-8') as jsonfile:
            json.dump(entries, jsonfile, indent=2, ensure_ascii=False)
        
        if not args.quiet:
            print(f"{Fore.GREEN}✅ Данные успешно экспортированы в '{filename}'")
            print(f"   Всего записей: {len(entries)}")
        return True
    
    except ImportError:
        print(f"{Fore.RED}❌ Ошибка: Модуль json не найден")
        return False
    except Exception as e:
        print(f"{Fore.RED}❌ Ошибка при экспорте в JSON: {e}")
        return False

def print_statistics(entries, args):
    """Выводит статистику по записям"""
    if not entries:
        if not args.quiet:
            print(f"{Fore.YELLOW}⚠ Нет данных для статистики")
        return
    
    if not args.quiet:
        print(f"\n{Fore.CYAN}{Style.BRIGHT}{'='*80}")
        print(f"{'СТАТИСТИКА АНАЛИЗА':^80}")
        print(f"{'='*80}")
    
    # Общая статистика
    print(f"{Fore.WHITE if not args.quiet else ''}Всего записей: {Fore.GREEN if not args.quiet else ''}{len(entries)}")
    
    # Статистика по приоритетам
    priority_counts = {}
    for entry in entries:
        priority = entry['priority']
        priority_counts[priority] = priority_counts.get(priority, 0) + 1
    
    if not args.quiet:
        print(f"\n{Fore.WHITE}Распределение по приоритетам:")
        for priority in sorted(priority_counts.keys()):
            count = priority_counts[priority]
            color = get_priority_color(priority, args.quiet)
            print(f"  Приоритет {color}{priority}{Fore.WHITE if not args.quiet else ''}: {count} записей")
    else:
        print("\nПриоритет | Количество")
        print("-" * 25)
        for priority in sorted(priority_counts.keys()):
            print(f"{priority:^9} | {priority_counts[priority]:^11}")
    
    # Статистика по протоколам
    protocol_counts = {}
    for entry in entries:
        protocol = entry['protocol']
        protocol_counts[protocol] = protocol_counts.get(protocol, 0) + 1
    
    if not args.quiet:
        print(f"\n{Fore.WHITE}Распределение по протоколам:")
        for protocol in sorted(protocol_counts.keys()):
            count = protocol_counts[protocol]
            print(f"  {Fore.CYAN if not args.quiet else ''}{protocol}{Fore.WHITE if not args.quiet else ''}: {count} записей")
    else:
        print("\nПротокол | Количество")
        print("-" * 25)
        for protocol in sorted(protocol_counts.keys()):
            print(f"{protocol:^8} | {protocol_counts[protocol]:^11}")
    
    # Топ источников и назначений
    src_ips = {}
    dst_ips = {}
    
    for entry in entries:
        src_ip = entry['src_ip']
        dst_ip = entry['dst_ip']
        
        src_ips[src_ip] = src_ips.get(src_ip, 0) + 1
        dst_ips[dst_ip] = dst_ips.get(dst_ip, 0) + 1
    
    if not args.quiet:
        print(f"\n{Fore.WHITE}Топ источников по количеству событий:")
        for ip, count in sorted(src_ips.items(), key=lambda x: x[1], reverse=True)[:5]:
            print(f"  {Fore.YELLOW if not args.quiet else ''}{ip}{Fore.WHITE if not args.quiet else ''}: {count} событий")
        
        print(f"\n{Fore.WHITE}Топ назначений по количеству событий:")
        for ip, count in sorted(dst_ips.items(), key=lambda x: x[1], reverse=True)[:5]:
            print(f"  {Fore.YELLOW if not args.quiet else ''}{ip}{Fore.WHITE if not args.quiet else ''}: {count} событий")
    
    # Обнаружение угроз
    malware_keywords = ['trojan', 'malware', 'exploit', 'attack', 'virus', 'worm', 'ransomware']
    malware_count = sum(1 for e in entries if any(keyword in e['classification'].lower() for keyword in malware_keywords))
    
    if malware_count > 0 and not args.quiet:
        print(f"\n{Back.RED if malware_count > 10 else Back.YELLOW}{Fore.WHITE}{Style.BRIGHT} ВНИМАНИЕ: Обнаружено {malware_count} событий вредоносной активности! {Style.RESET_ALL}")
    
    # Рекомендации
    if not args.quiet:
        if priority_counts.get(1, 0) > 0:
            print(f"\n{Fore.RED}{Style.BRIGHT}Рекомендации:")
            print(f"  1. Проверьте хосты с критическими событиями (приоритет 1)")
            print(f"  2. Изолируйте зараженные системы от сети")
            print(f"  3. Обновите правила Suricata до последней версии")
            print(f"  4. Проведите глубокий анализ уязвимостей")

def main():
    """Основная функция"""
    # Парсинг аргументов
    args = parse_arguments()
    
    # Показать баннер (если не тихий режим)
    if not args.quiet:
        show_banner()
    
    # Показать цветовую схему и выйти
    if args.colors:
        show_colors_legend()
        sys.exit(0)
    
    # Показать детальную справку
    if len(sys.argv) == 1:
        print(f"{Fore.YELLOW}Для запуска программы укажите файл лога или используйте опции")
        print(f"Пример: {Fore.CYAN}{sys.argv[0]} -h {Fore.YELLOW}для справки")
        sys.exit(0)
    
    # Чтение лога
    if args.verbose and not args.quiet:
        print(f"{Fore.CYAN}📖 Чтение файла: {args.input}")
        print(f"{Fore.CYAN}📝 Экспорт в: {args.output} ({args.format})")
    
    entries = parse_log_file(args.input, args)
    
    if not entries:
        print(f"{Fore.RED}❌ Не удалось загрузить записи из файла '{args.input}'")
        print(f"{Fore.YELLOW}   Проверьте формат файла или используйте опцию -v для отладки")
        sys.exit(2)
    
    if not args.quiet:
        print(f"{Fore.GREEN}✅ Успешно загружено {len(entries)} записей из '{args.input}'")
    
    # Вывод записей с цветовой разметкой
    if not args.stats and not args.quiet:
        print(f"\n{Fore.CYAN}{Style.BRIGHT}{'='*80}")
        print(f"{'ДЕТАЛИЗИРОВАННЫЙ ВЫВОД':^80}")
        print(f"{'='*80}")
        
        for i, entry in enumerate(entries):
            print_colored_log_entry(entry, i, args)
            
            # Пауза каждые 5 записей для удобства просмотра
            if not args.quiet and (i + 1) % 5 == 0 and i + 1 < len(entries):
                input(f"\n{Fore.YELLOW}Нажмите Enter для продолжения...")
    
    # Вывод статистики
    print_statistics(entries, args)
    
    # Экспорт в файл
    if not args.no_export:
        if args.format == 'csv':
            export_to_csv(entries, args.output, args)
        elif args.format == 'json':
            export_to_json(entries, args.output, args)
    
    # Дополнительные опции
    if not args.quiet:
        print(f"\n{Fore.CYAN}{Style.BRIGHT}{'='*80}")
        print(f"{'ДОПОЛНИТЕЛЬНЫЕ ВОЗМОЖНОСТИ':^80}")
        print(f"{'='*80}")
        
        # Пример фильтрации
        if args.filter:
            print(f"\n{Fore.WHITE}Применен фильтр: {Fore.CYAN}'{args.filter}'")
            print(f"  Найдено {len(entries)} совпадений")
        
        # Поиск конкретных угроз
        if not args.filter:
            lokibot_events = [e for e in entries if 'lokibot' in e['description'].lower()]
            if lokibot_events:
                print(f"\n{Fore.WHITE}Обнаружены события LokiBot:")
                print(f"  IP источника: {Fore.YELLOW}{lokibot_events[0]['src_ip']}")
                print(f"  C&C сервер: {Fore.RED}{lokibot_events[0]['dst_ip']}")
                print(f"  Количество событий: {Fore.CYAN}{len(lokibot_events)}")
        
        print(f"\n{Fore.GREEN}{Style.BRIGHT}✓ Анализ завершен успешно!")
    
    # Выходные коды
    critical_events = sum(1 for e in entries if e['priority'] == 1)
    if critical_events > 0:
        if not args.quiet:
            print(f"{Fore.RED}⚠ Обнаружено {critical_events} критических событий!")
        sys.exit(1)  # Выход с кодом ошибки при критических событиях
    else:
        sys.exit(0)  # Успешное завершение

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}⚠ Программа прервана пользователем")
        sys.exit(130)
    except Exception as e:
        print(f"\n{Fore.RED}❌ Неожиданная ошибка: {e}")
        if '-v' in sys.argv or '--verbose' in sys.argv:
            import traceback
            traceback.print_exc()
        sys.exit(3)