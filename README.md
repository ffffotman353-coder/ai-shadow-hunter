# 🔍 AI-SHADOW-HUNTER v7.0

## أداة فحص أمان متقدمة لاختبار OWASP Top 10 مع اكتشاف تلقائي للـ Parameters

![Version](https://img.shields.io/badge/version-7.0-blue)
![License](https://img.shields.io/badge/license-MIT-green)
![Python](https://img.shields.io/badge/python-3.8%2B-blue)
![Status](https://img.shields.io/badge/status-Active-brightgreen)

---

## 📋 المحتويات

- [المميزات](#-المميزات)
- [المتطلبات](#-المتطلبات)
- [التثبيت](#-التثبيت)
- [الاستخدام](#-الاستخدام)
- [أمثلة](#-أمثلة)
- [اختبارات OWASP Top 10](#-اختبارات-owasp-top-10)
- [المساهمة](#-المساهمة)
- [التحذير القانوني](#-التحذير-القانوني)

---

## 🚀 المميزات

### ✨ الميزات الأساسية

✅ **اكتشاف تلقائي للـ Parameters**
- يكتشف الـ parameters من الـ URLs تلقائياً
- يستخرج الـ parameters من HTML forms و AJAX endpoints
- يحلل الـ query strings و POST data

✅ **اختبارات OWASP Top 10 الشاملة**
- **A01: SQL Injection** - Error-based و Time-based Blind
- **A02: Broken Authentication** - اختبار الـ weak credentials
- **A03: Sensitive Data Exposure** - البحث عن الملفات الحساسة
- **A04: XXE Injection** - اختبار XML External Entity
- **A05: SSRF** - Server-Side Request Forgery
- **A06: Path Traversal** - Directory traversal attacks
- **A07: Command Injection** - OS command injection
- **A08: Security Misconfiguration** - فحص الإعدادات الأمنية
- **A09: Broken Access Control** - فحص صلاحيات الوصول
- **A10: Known Vulnerabilities** - البحث عن مكونات قديمة

✅ **فحص المنافذ (Port Scanning)**
- فحص المنافذ الشهيرة بالتوازي
- تحديد الخدمات على كل منفذ
- تقرير تفصيلي للمنافذ المفتوحة

✅ **كشف الـ Subdomains**
- Brute force DNS للـ subdomains الشهيرة
- اختبار الاتصالات HTTP/HTTPS
- تقرير شامل للـ subdomains المكتشفة

✅ **تقارير متقدمة**
- تقارير JSON مفصّلة
- تقارير HTML جميلة وملونة
- ملخص سريع للنتائج بترتيب حسب الخطورة

---

## 📊 الإحصائيات
