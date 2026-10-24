"""Завдання 2: Багаторівнева система контролю доступу (Варіант 15)."""

# Вхідні дані для 15 варіанту
USERS = {
    "quantum_researcher": {
        "role": "quantum_security",
        "clearance": 4,
        "department": "Quantum Research",
        "active": True,
    },
    "post_quantum_dev": {
        "role": "pq_cryptographer",
        "clearance": 4,
        "department": "Post-Quantum",
        "active": True,
    },
    "network_security": {
        "role": "network_security",
        "clearance": 3,
        "department": "Network Security",
        "active": True,
    },
    "crypto_intern": {
        "role": "crypto_intern",
        "clearance": 1,
        "department": "Internship",
        "active": True,
    },
    "quantum_sim": {
        "role": "simulator",
        "clearance": 2,
        "department": "Simulation",
        "active": False,
    },
}

RESOURCES = [
    ("quantum_algorithms", 4),
    ("pq_implementations", 4),
    ("network_protocols", 3),
    ("learning_materials", 1),
    ("quantum_keys", 4),
    ("educational_content", 1),
    ("hybrid_systems", 3),
    ("quantum_computers", 4),
    ("crypto_libraries", 2),
    ("tutorials", 1),
]

SECURITY_LEVELS = (
    "Educational",
    "Research",
    "Classified Research",
    "Quantum Secure",
)

BLOCKED_USERS = {"quantum_sim", "quantum_attack", "algorithm_theft"}


def display_resources() -> None:
    """Виводить список ресурсів із текстовими позначеннями рівнів доступу."""
    print("\n- Завдання 2 -")
    print("\n- Список ресурсів системи -")
    print(f"{'Ресурс':<24} | {'Рівень безпеки'}")
    print("-" * 55)
    for res_name, level_idx in RESOURCES:
        text_level = SECURITY_LEVELS[level_idx - 1]
        print(f"{res_name:<24} | {text_level} ({level_idx})")


def check_access(username: str, resource: tuple[str, int]) -> tuple[bool, str]:
    """Перевіряє доступ конкретного користувача до конкретного ресурсу."""
    _, res_level = resource

    if username not in USERS:
        return False, "User not found"

    if username in BLOCKED_USERS:
        return False, "User is blocked"

    user_info = USERS[username]

    if not user_info.get("active", False):
        return False, "Account inactive"

    if user_info.get("clearance", 0) >= res_level:
        return True, "Access granted"

    return False, "Insufficient clearance"


def run_task2() -> None:
    """Запускає повний цикл перевірки доступу."""
    display_resources()

    print("\n- Результати перевірки доступу -")
    print("-" * 75)

    test_users = list(USERS.keys()) + ["external_intruder"]

    for user in test_users:
        for resource in RESOURCES:
            allowed, reason = check_access(user, resource)
            res_name = resource[0]
            if allowed:
                verdict = "ALLOW"
            else:
                verdict = f"DENY ({reason})"

            print(f"user={user:<20} resource={res_name:<22} -> {verdict}")


if __name__ == "__main__":
    run_task2()
