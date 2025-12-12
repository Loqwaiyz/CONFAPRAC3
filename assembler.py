import argparse
import re
import json
from typing import List, Dict, Any

# --- 1. СПЕЦИФИКАЦИЯ КОМАНД УВМ ---
# Словарь для маппинга мнемоник на код операции (A), формат и поля.
# Обратите внимание: тестовые байтовые последовательности подобраны
# для соответствия требованиям спецификации.

COMMAND_SPEC = {
    # 1. Загрузка константы (LDC): A=4. Формат: 5 байт.
    # Поля: A(0-3), B(4-10: Адрес), C(11-36: Константа).
    "LDC": {
        "A": 4, 
        "format": "R[{B}] = {C}",
        "fields": ["B", "C"],
        "byte_size": 5,
        "test_fields": {"A": 4, "B": 91, "C": 651}, # Тест A=4, B=91, C=651
        # 0xE4, 0x5D, 0x14, 0x00, 0x00 (используя 0x14 вместо 8x14)
        "test_bytes": [0xE4, 0x5D, 0x14, 0x00, 0x00] 
    },
    
    # 2. Чтение из памяти (LDM): A=14. Формат: 4 байта.
    # Поля: A(0-3), B(4-18: Адрес памяти), C(19-25: Адрес регистра).
    "LDM": {
        "A": 14, 
        "format": "R[{C}] = M[{B}]",
        "fields": ["C", "B"], 
        "byte_size": 4,
        "test_fields": {"A": 14, "B": 820, "C": 53}, # Тест A=14, B=820, C=53
        "test_bytes": [0x4E, 0x33, 0xA8, 0x01] 
    },
    
    # 3. Запись в память (STM): A=10. Формат: 3 байта.
    # Поля: A(0-3), B(4-10: Регистр с адресом памяти), C(11-17: Регистр со значением).
    "STM": {
        "A": 10, 
        "format": "M[R[{B}]] = R[{C}]",
        "fields": ["B", "C"],
        "byte_size": 3,
        "test_fields": {"A": 10, "B": 5, "C": 8}, # Тест A=10, B=5, C=8
        "test_bytes": [0x5A, 0x98, 0x02]
    },
    
    # 4. Бинарная операция (BIN_OP): A=5. Формат: 4 байта.
    # Поля: A(0-3), B(4-10: Регистр с базой), C(11-20: Смещение), D(21-27: Регистр/Результат).
    "BIN_OP": {
        "A": 5, 
        "format": "R[{D}], R[{B}], {C}",
        "fields": ["D", "B", "C"],
        "byte_size": 4,
        "test_fields": {"A": 5, "B": 85, "C": 310, "D": 6}, # Тест A=5, B=85, C=310, D=6
        "test_bytes": [0x55, 0xB5, 0xA9, 0x07]
    },
}

# --- 2. ФУНКЦИИ АССЕМБЛЕРА (ЭТАП 1) ---

def parse_line(line: str, line_num: int) -> Dict[str, Any] | None:
    """Разбирает одну строку ассемблерного кода в словарь полей (Промежуточное Представление)."""
    line = line.strip()
    if not line or line.startswith('#'):
        return None

    parts = line.split(maxsplit=1)
    if not parts:
        return None

    mnemonic = parts[0].upper()
    operand_string = parts[1] if len(parts) > 1 else ""

    if mnemonic not in COMMAND_SPEC:
        raise ValueError(f"Ошибка в строке {line_num}: Неизвестная мнемоника '{mnemonic}'")

    spec = COMMAND_SPEC[mnemonic]
    fields = {}
    
    # Регулярные выражения для парсинга операндов
    if mnemonic == "LDC":
        # R[B] = C
        match = re.fullmatch(r"R\[(\d+)\]\s*=\s*(\d+)", operand_string)
        if not match:
            raise SyntaxError(f"Ошибка в строке {line_num}: Неверный синтаксис LDC. Ожидался 'R[B] = C'")
        fields['B'] = int(match.group(1))
        fields['C'] = int(match.group(2))
        
    elif mnemonic == "LDM":
        # R[C] = M[B]
        match = re.fullmatch(r"R\[(\d+)\]\s*=\s*M\[(\d+)\]", operand_string)
        if not match:
            raise SyntaxError(f"Ошибка в строке {line_num}: Неверный синтаксис LDM. Ожидался 'R[C] = M[B]'")
        fields['C'] = int(match.group(1)) # Регистр назначения (C)
        fields['B'] = int(match.group(2)) # Адрес памяти (B)
        
    elif mnemonic == "STM":
        # M[R[B]] = R[C]
        match = re.fullmatch(r"M\[R\[(\d+)\]\]\s*=\s*R\[(\d+)\]", operand_string)
        if not match:
            raise SyntaxError(f"Ошибка в строке {line_num}: Неверный синтаксис STM. Ожидался 'M[R[B]] = R[C]'")
        fields['B'] = int(match.group(1)) # Регистр с адресом памяти (B)
        fields['C'] = int(match.group(2)) # Регистр со значением (C)
        
    elif mnemonic == "BIN_OP":
        # R[D], R[B], C
        match = re.fullmatch(r"R\[(\d+)\],\s*R\[(\d+)\],\s*(\d+)", operand_string)
        if not match:
            raise SyntaxError(f"Ошибка в строке {line_num}: Неверный синтаксис BIN_OP. Ожидался 'R[D], R[B], C'")
        fields['D'] = int(match.group(1))
        fields['B'] = int(match.group(2))
        fields['C'] = int(match.group(3))
        
    # Формирование промежуточного представления (ПП)
    pp_entry = {
        "mnemonic": mnemonic,
        "A": spec["A"],
        "byte_size": spec["byte_size"]
    }
    pp_entry.update(fields)
    return pp_entry


def assemble_to_pp(source_path: str) -> List[Dict[str, Any]]:
    """Читает исходный файл и транслирует его в промежуточное представление."""
    intermediate_representation = []
    
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
            print(f"Критическая ошибка ассемблирования в строке {i}: {e}")
            return []
            
    return intermediate_representation

# --- 3. ФУНКЦИЯ ГЕНЕРАЦИИ МАШИННОГО КОДА (ЭТАП 2) ---

def generate_machine_code(pp_entry: Dict[str, Any]) -> bytes:
    """
    Преобразует запись промежуточного представления (ПП) в двоичную байтовую строку.
    Использует побитовые операции согласно спецификации УВМ (little-endian).
    """
    mnemonic = pp_entry["mnemonic"]
    
    # Поле A всегда находится в битах 0-3.
    instruction_word = pp_entry["A"] 
    size = pp_entry["byte_size"]
    
    if mnemonic == "LDC":
        # A (0-3), B (4-10), C (11-36)
        instruction_word |= (pp_entry["B"] << 4)
        instruction_word |= (pp_entry["C"] << 11)
        
    elif mnemonic == "LDM":
        # A (0-3), B (4-18), C (19-25)
        instruction_word |= (pp_entry["B"] << 4)
        instruction_word |= (pp_entry["C"] << 19)
        
    elif mnemonic == "STM":
        # A (0-3), B (4-10), C (11-17)
        instruction_word |= (pp_entry["B"] << 4)
        instruction_word |= (pp_entry["C"] << 11)
        
    elif mnemonic == "BIN_OP":
        # A (0-3), B (4-10), C (11-20), D (21-27)
        instruction_word |= (pp_entry["B"] << 4)
        instruction_word |= (pp_entry["C"] << 11)
        instruction_word |= (pp_entry["D"] << 21)
        
    # Преобразование машинного слова (целого числа) в байты (little-endian)
    return instruction_word.to_bytes(size, byteorder='little')


# --- 4. РЕЖИМ ТЕСТИРОВАНИЯ (ЭТАПЫ 1 И 2) ---

def run_tests(pp_list: List[Dict[str, Any]]):
    """Проверяет и выводит ПП (Этап 1) и сгенерированный байт-код (Этап 2)."""
    
    # 1. Проверка Промежуточного Представления (Этап 1)
    print("\n--- 📝 РЕЖИМ ТЕСТИРОВАНИЯ (Промежуточное представление) ---")
    
    expected_pp_entries = [
        COMMAND_SPEC["LDC"]["test_fields"],
        COMMAND_SPEC["LDM"]["test_fields"],
        COMMAND_SPEC["STM"]["test_fields"],
        COMMAND_SPEC["BIN_OP"]["test_fields"],
    ]
    
    if len(pp_list) < len(expected_pp_entries):
        print("Тест на количество команд: ❌ НЕУДАЧА. Ожидалось: 4.")
        print("---")
        return

    all_fields_passed = True
    
    for i, expected in enumerate(expected_pp_entries):
        actual = pp_list[i]
        actual_fields = {k: v for k, v in actual.items() if k in expected}
        
        match = (expected == actual_fields)
        status = "✅ ПРОЙДЕН" if match else "❌ НЕУДАЧА"
        all_fields_passed = all_fields_passed and match
        
        print(f"Команда {i+1} ({actual['mnemonic']}): Поля {status}")
        print(f"  Ожидаемые поля: {expected}")
        print(f"  Фактические поля: {actual_fields}")
    
    if all_fields_passed:
        print("\n🎉 ВСЕ ТЕСТЫ ПОЛЕЙ УСПЕШНО ПРОЙДЕНЫ!")
    print("-------------------------------------------------")


    # 2. Проверка Байтовых Последовательностей (Этап 2)
    print("\n--- 💾 РЕЖИМ ТЕСТИРОВАНИЯ (Байтовые последовательности) ---")
    
    all_bytes_passed = True
    
    for i, pp_entry in enumerate(pp_list):
        mnemonic = pp_entry["mnemonic"]
        expected_bytes_list = COMMAND_SPEC[mnemonic]["test_bytes"]
        
        try:
            actual_bytes = generate_machine_code(pp_entry)
        except Exception as e:
            print(f"Ошибка генерации байт-кода для {mnemonic}: {e}")
            all_bytes_passed = False
            continue
            
        actual_bytes_list = list(actual_bytes)
        
        match = (expected_bytes_list == actual_bytes_list)
        status = "✅ ПРОЙДЕН" if match else "❌ НЕУДАЧА"
        all_bytes_passed = all_bytes_passed and match
        
        print(f"Команда {i+1} ({mnemonic}): Байты {status}")
        print(f"  Ожидаемые байты: {[hex(b) for b in expected_bytes_list]}")
        print(f"  Фактические байты: {[hex(b) for b in actual_bytes_list]}")
        
    if all_bytes_passed:
        print("\n🎉 ВСЕ ТЕСТЫ БАЙТОВЫХ ПОСЛЕДОВАТЕЛЬНОСТЕЙ УСПЕШНО ПРОЙДЕНЫ!")
    print("-------------------------------------------------")


# --- 5. CLI И ГЛАВНАЯ ФУНКЦИЯ ---

def main():
    """Главная функция CLI-приложения ассемблера."""
    # 1. Обработка аргументов командной строки (Требования 31-34)
    parser = argparse.ArgumentParser(description="Ассемблер УВМ (Этапы 1-2)")
    parser.add_argument("source_file", help="Путь к исходному файлу с текстом программы.")
    parser.add_argument("binary_output", help="Путь к двоичному файлу-результату.")
    parser.add_argument("--test_mode", action="store_true", help="Режим тестирования: вывод ПП и байт-кода на экран.")
    
    args = parser.parse_args()
    
    # 2. Трансляция в ПП (Этап 1)
    pp_list = assemble_to_pp(args.source_file)
    if not pp_list: return
    
    # 3. Формирование машинного кода (Этап 2)
    machine_code = b''
    for pp_entry in pp_list:
        try:
            machine_code += generate_machine_code(pp_entry)
        except Exception as e:
            print(f"Критическая ошибка при генерации машинного кода: {e}")
            return

    # 4. Запись в файл (Требование 48)
    try:
        with open(args.binary_output, 'wb') as f:
            f.write(machine_code)
        print(f"\n✅ Результат записан в двоичный файл: {args.binary_output}")
    except IOError:
        print(f"Ошибка записи в выходной файл: {args.binary_output}")
        return

    # 5. Вывод числа команд (Требование 49)
    print(f"📊 Число ассемблированных команд: {len(pp_list)}")

    # 6. Режим тестирования (Требования 39, 50, 51)
    if args.test_mode:
        run_tests(pp_list)
    else:
        print("Ассемблирование завершено.")


if __name__ == "__main__":
    main()