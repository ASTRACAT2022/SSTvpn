#!/usr/bin/env python3
"""
Скрипт инициализации чистой базы данных для новых пользователей.
Создает все таблицы и инициализирует дефолтные настройки.

Включает все поля из миграций:
- migrate_add_badge.py: Tariff.badge
- migrate_add_promo_code_id.py: Payment.promo_code_id
- migrate_add_heleket.py: PaymentSetting.heleket_api_key, Payment.payment_provider
- migrate_add_telegram_bot_token.py: PaymentSetting.telegram_bot_token

Использование:
    python3 init_db.py
"""

import os
import sys
import json
from datetime import datetime, timezone
from dotenv import load_dotenv

# Загружаем переменные окружения
load_dotenv()

# Импортируем Flask app и модели
from app import app, db, bcrypt, fernet
from app import (
    User, Tariff, PromoCode, ReferralSetting, TariffFeatureSetting,
    Ticket, TicketMessage, PaymentSetting, SystemSetting, Payment
)

def init_database():
    """
    Создает все таблицы базы данных и инициализирует дефолтные настройки.
    """
    print("=" * 60)
    print("  Инициализация базы данных StealthNET Admin Panel")
    print("=" * 60)
    print()
    
    with app.app_context():
        # Проверяем, существует ли база данных
        db_path = app.config['SQLALCHEMY_DATABASE_URI'].replace('sqlite:///', '')
        if os.path.exists(db_path):
            response = input(f"⚠️  База данных уже существует: {db_path}\n"
                           f"   Вы хотите удалить её и создать новую? (yes/no): ")
            if response.lower() in ['yes', 'y', 'да']:
                try:
                    os.remove(db_path)
                    print(f"✓ База данных удалена: {db_path}")
                except Exception as e:
                    print(f"❌ Ошибка при удалении базы данных: {e}")
                    return False
            else:
                print("❌ Отмена операции. База данных не изменена.")
                return False
        
        print("\n📦 Создание всех таблиц...")
        print("   Создаются следующие таблицы:")
        print("   - user (пользователи)")
        print("   - tariff (тарифы, включая поле badge)")
        print("   - promo_code (промокоды)")
        print("   - payment (платежи, включая promo_code_id и payment_provider)")
        print("   - payment_setting (настройки платежей, включая heleket_api_key и telegram_bot_token)")
        print("   - referral_setting (настройки реферальной программы)")
        print("   - tariff_feature_setting (настройки функций тарифов)")
        print("   - system_setting (системные настройки)")
        print("   - ticket (тикеты поддержки)")
        print("   - ticket_message (сообщения в тикетах)")
        print()
        try:
            # Создаем все таблицы (включая все поля из миграций)
            db.create_all()
            print("✓ Все таблицы успешно созданы")
        except Exception as e:
            print(f"❌ Ошибка при создании таблиц: {e}")
            return False
        
        print("\n⚙️  Инициализация дефолтных настроек...")
        
        # 1. SystemSetting (системные настройки)
        try:
            if not SystemSetting.query.first():
                system_setting = SystemSetting(
                    id=1,
                    default_language='ru',
                    default_currency='uah'
                )
                db.session.add(system_setting)
                db.session.commit()
                print("✓ SystemSetting инициализирован (язык: ru, валюта: uah)")
            else:
                print("✓ SystemSetting уже существует")
        except Exception as e:
            print(f"❌ Ошибка при инициализации SystemSetting: {e}")
            db.session.rollback()
        
        # 2. ReferralSetting (настройки реферальной программы)
        try:
            if not ReferralSetting.query.first():
                referral_setting = ReferralSetting(
                    invitee_bonus_days=7,
                    referrer_bonus_days=7,
                    trial_squad_id=None
                )
                db.session.add(referral_setting)
                db.session.commit()
                print("✓ ReferralSetting инициализирован (бонус: 7 дней)")
            else:
                print("✓ ReferralSetting уже существует")
        except Exception as e:
            print(f"❌ Ошибка при инициализации ReferralSetting: {e}")
            db.session.rollback()
        
        # 3. PaymentSetting (настройки платежных систем)
        try:
            if not PaymentSetting.query.first():
                payment_setting = PaymentSetting(id=1)
                db.session.add(payment_setting)
                db.session.commit()
                print("✓ PaymentSetting инициализирован (id: 1)")
            else:
                print("✓ PaymentSetting уже существует")
        except Exception as e:
            print(f"❌ Ошибка при инициализации PaymentSetting: {e}")
            db.session.rollback()
        
        # 4. TariffFeatureSetting (настройки функций тарифов)
        try:
            # Создаем дефолтные функции для каждого уровня
            tiers = ['basic', 'pro', 'elite']
            default_features = {
                'basic': [
                    "Базовый уровень защиты",
                    "Стандартные серверы",
                    "Базовая поддержка"
                ],
                'pro': [
                    "Продвинутый уровень защиты",
                    "Приоритетные серверы",
                    "Приоритетная поддержка",
                    "Дополнительные функции"
                ],
                'elite': [
                    "Максимальный уровень защиты",
                    "Премиум серверы",
                    "24/7 приоритетная поддержка",
                    "Все функции Pro",
                    "Эксклюзивные возможности"
                ]
            }
            
            for tier in tiers:
                if not TariffFeatureSetting.query.filter_by(tier=tier).first():
                    features_json = json.dumps(default_features[tier], ensure_ascii=False)
                    tariff_feature = TariffFeatureSetting(
                        tier=tier,
                        features=features_json
                    )
                    db.session.add(tariff_feature)
                    db.session.commit()
                    print(f"✓ TariffFeatureSetting для '{tier}' инициализирован")
                else:
                    print(f"✓ TariffFeatureSetting для '{tier}' уже существует")
        except Exception as e:
            print(f"❌ Ошибка при инициализации TariffFeatureSetting: {e}")
            db.session.rollback()
        
        print("\n" + "=" * 60)
        print("✅ Инициализация базы данных завершена успешно!")
        print("=" * 60)
        print("\n📝 Следующие шаги:")
        print("   1. Создайте администратора:")
        print("      python3 -m flask --app app make-admin ВАШ_EMAIL")
        print("   2. Запустите приложение:")
        print("      python3 app.py")
        print("      или")
        print("      gunicorn --workers 3 --bind 127.0.0.1:5000 app:app")
        print()
        
        return True


def main():
    """Главная функция"""
    try:
        success = init_database()
        if success:
            sys.exit(0)
        else:
            sys.exit(1)
    except KeyboardInterrupt:
        print("\n\n❌ Операция прервана пользователем")
        sys.exit(1)
    except Exception as e:
        print(f"\n❌ Критическая ошибка: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()

