import argparse
import re
import json
from typing import List, Dict, Any

# --- 1. СПЕЦИФИКАЦИЯ КОМАНД УВМ ---
# Словарь для маппинга мнемоник на код операции (A) и формат полей.
COMMAND_SPEC = {
    # LDC R[B] = C
    "LDC": {
        "A": 4, 
        "format": "R[{B}] = {C}",
        "fields": ["B", "C"],
        "byte_size": 5, # Размер команды: 5 байт [cite: 7]
        "test_fields": {"A": 4, "B": 91, "C": 651}
    },
    # LDM R[C] = M[B]
    "LDM": {
        "A": 14, 
        "format": "R[{C}] = M[{B}]",
        "fields": ["C", "B"], # Порядок в синтаксисе: R[C] = M[B]. Поля: B (Адрес памяти), C (Адрес регистра) [cite: 11, 13]
        "byte_size": 4, # Размер команды: 4 байта [cite: 12]
        "test_fields": {"A": 14, "B": 820, "C": 53}
    },
    # STM M[R[B]] = R[C]
    "STM": {
        "A": 10, 
        "format": "M[R[{B}]] = R[{C}]",
        "fields": ["B", "C"],
        "byte_size": 3, # Размер команды: 3 байта [cite: 18]
        # B: Адрес регистра с адресом памяти. C: Адрес регистра со значением. [cite: 17, 19]
        "test_fields": {"A": 10, "B": 5, "C": 8}
    },
    # BIN_OP R[D], R[B], C (R[D] = R[D] > M[R[B] + C])
    "BIN_OP": {
        "A": 5, 
        "format": "R[{D}], R[{B}], {C}",
        "fields": ["D", "B", "C"],
        "byte_size": 4, # Размер команды: 4 байта [cite: 25]
        # D: Регистр-результат/операнд. B: Регистр с базой. C: Смещение. [cite: 23, 25, 26]
        "test_fields": {"A": 5, "B": 85, "C": 310, "D": 6}
    },
}

# --- 2. ФУНКЦИИ АССЕМБЛЕРА ---

def parse_line(line: str, line_num: int) -> Dict[str, Any] | None:
    """Разбирает одну строку ассемблерного кода в словарь полей."""
    line = line.strip()
    if not line or line.startswith('#'):
        return None  # Пропускаем пустые строки и комментарии

    parts = line.split(maxsplit=1)
    if not parts:
        return None

    mnemonic = parts[0].upper()
    operand_string = parts[1] if len(parts) > 1 else ""

    if mnemonic not in COMMAND_SPEC:
        raise ValueError(f"Ошибка в строке {line_num}: Неизвестная мнемоника '{mnemonic}'")

    spec = COMMAND_SPEC[mnemonic]
    
    # Регулярные выражения для извлечения значений из операндов
    # Шаблоны для R[N], M[N], M[R[N]], M[R[N] + K] и простых констант.
    
    fields = {}
    
    if mnemonic == "LDC":
        # Ожидаем R[B] = C
        match = re.fullmatch(r"R\[(\d+)\]\s*=\s*(\d+)", operand_string)
        if not match:
            raise SyntaxError(f"Ошибка в строке {line_num}: Неверный синтаксис LDC. Ожидался 'R[B] = C'")
        fields['B'] = int(match.group(1))
        fields['C'] = int(match.group(2))
        
    elif mnemonic == "LDM":
        # Ожидаем R[C] = M[B]
        match = re.fullmatch(r"R\[(\d+)\]\s*=\s*M\[(\d+)\]", operand_string)
        if not match:
            raise SyntaxError(f"Ошибка в строке {line_num}: Неверный синтаксис LDM. Ожидался 'R[C] = M[B]'")
        fields['C'] = int(match.group(1)) # Регистр назначения (C) [cite: 13]
        fields['B'] = int(match.group(2)) # Адрес памяти (B) [cite: 12]
        
    elif mnemonic == "STM":
        # Ожидаем M[R[B]] = R[C]
        match = re.fullmatch(r"M\[R\[(\d+)\]\]\s*=\s*R\[(\d+)\]", operand_string)
        if not match:
            # Обратите внимание: Результат: значение в памяти по адресу, которым является РЕГИСТР по адресу, которым является поле B. [cite: 19]
            # Это косвенная адресация, поэтому синтаксис сложный.
            raise SyntaxError(f"Ошибка в строке {line_num}: Неверный синтаксис STM. Ожидался 'M[R[B]] = R[C]'")
        fields['B'] = int(match.group(1)) # Регистр с адресом памяти (B) [cite: 17]
        fields['C'] = int(match.group(2)) # Регистр со значением (C) [cite: 18]
        
    elif mnemonic == "BIN_OP":
        # Ожидаем R[D], R[B], C (операнды)
        # Соответствует логике R[D] = R[D] > M[R[B] + C]
        match = re.fullmatch(r"R\[(\d+)\],\s*R\[(\d+)\],\s*(\d+)", operand_string)
        if not match:
            raise SyntaxError(f"Ошибка в строке {line_num}: Неверный синтаксис BIN_OP. Ожидался 'R[D], R[B], C'")
        fields['D'] = int(match.group(1))
        fields['B'] = int(match.group(2))
        fields['C'] = int(match.group(3))
        
    # Формирование промежуточного представления
    pp_entry = {
        "mnemonic": mnemonic,
        "A": spec["A"],
    }
    pp_entry.update(fields)
    return pp_entry


def assemble_to_pp(source_path: str) -> List[Dict[str, Any]]:
    """Читает исходный файл и транслирует его в промежуточное представление."""
    intermediate_representation = [] # Внутреннее представление (список словарей) 
    
    try:
        with open(source_path, 'r', encoding='utf-8') as f:
            lines = f.readlines()
    except FileNotFoundError:
        print(f"Ошибка: Исходный файл не найден по пути: {source_path}")
        return []

    for i, line in enumerate(lines, 1):
        try:
            pp_entry = parse_line(line, i)
            if pp_entry:
                intermediate_representation.append(pp_entry)
        except (ValueError, SyntaxError) as e:
            print(f"Критическая ошибка ассемблирования: {e}")
            return []
            
    return intermediate_representation


def run_tests(pp_list: List[Dict[str, Any]]):
    """Проверяет, соответствует ли ПП тестовым примерам из спецификации."""
    print("\n--- 📝 РЕЖИМ ТЕСТИРОВАНИЯ (Промежуточное представление)  ---")
    
    expected_pp_entries = [
        COMMAND_SPEC["LDC"]["test_fields"],
        COMMAND_SPEC["LDM"]["test_fields"],
        COMMAND_SPEC["STM"]["test_fields"],
        COMMAND_SPEC["BIN_OP"]["test_fields"],
    ]
    
    # Проверка количества команд
    if len(pp_list) < len(expected_pp_entries):
        print("Тест на количество команд: ❌ НЕУДАЧА.")
        print(f"Ожидалось: {len(expected_pp_entries)}, Получено: {len(pp_list)}")
        print("---")
        return

    all_passed = True
    
    for i, expected in enumerate(expected_pp_entries):
        if i >= len(pp_list):
            break # Если в файле меньше команд, чем в тестах
            
        actual = pp_list[i]
        
        # Фильтруем фактические поля, чтобы оставить только A, B, C, D
        actual_fields = {k: v for k, v in actual.items() if k in expected}
        
        match = (expected == actual_fields)
        
        status = "ПРОЙДЕН" if match else "НЕУДАЧА"
        all_passed = all_passed and match
        
        print(f"Команда {i+1} ({actual['mnemonic']}): {status}")
        print(f"  Ожидаемые поля: {expected}")
        print(f"  Фактические поля: {actual_fields}")
        if not match:
             print("  --> НЕ СОВПАДАЮТ ПОЛЯ ИЛИ ЗНАЧЕНИЯ")
        print("---")
        
    if all_passed:
        print("🎉 ВСЕ ТЕСТЫ ПЕРЕВОДА В ПП УСПЕШНО ПРОЙДЕНЫ!")
        
    print("\n--- ПОЛНОЕ ПРОМЕЖУТОЧНОЕ ПРЕДСТАВЛЕНИЕ (ПП) ---")
    print(json.dumps(pp_list, indent=4)) # Вывод внутреннего представления 
    print("-------------------------------------------------")


# --- 3. CLI И ГЛАВНАЯ ФУНКЦИЯ ---

def main():
    """Главная функция CLI-приложения ассемблера."""
    # 1. Обработка аргументов командной строки [cite: 31]
    parser = argparse.ArgumentParser(description="Ассемблер УВМ (Этап 1)")
    parser.add_argument("source_file", help="Путь к исходному файлу с текстом программы.")
    parser.add_argument("binary_output", help="Путь к двоичному файлу-результату.")
    parser.add_argument("--test_mode", action="store_true", help="Режим тестирования: вывод ПП на экран.")
    
    args = parser.parse_args()
    
    # 2. Трансляция в ПП
    pp_list = assemble_to_pp(args.source_file)
    
    if not pp_list:
        print("Трансляция не выполнена из-за ошибок.")
        return
    
    # 3. Режим тестирования
    if args.test_mode:
        # Требование 6: Продемонстрировать идентичные последовательности полей и их значений 
        run_tests(pp_list)
        return

    print("Ассемблирование завершено. Промежуточное представление готово.")
    # На Этапе 1 мы не записываем двоичный файл, но на Этапе 2 это будет сделано.
    print(f"Промежуточное представление: {len(pp_list)} команд.")


if __name__ == "__main__":
    # Для запуска этого кода вам нужно создать файл (например, 'test_program.asm')
    # и вызвать его из командной строки:
    # python <имя_файла_с_кодом>.py test_program.asm output.bin --test_mode
    main()