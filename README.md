***OktaGuard – Security Monitoring Service***

1️⃣ Prerequisites

Java 17+

Spring Boot 3.x

Okta Developer Account

Okta API Token (SSWS)

2️⃣ Configure application.yml
```
okta:
domain: https://your-domain.okta.com
api-token: YOUR_SSWS_API_TOKEN
client-id: YOUR_CLIENT_ID
client-secret: YOUR_CLIENT_SECRET
```

3️⃣ Run the app
```
mvn spring-boot:run
```

## API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | /api/okta/users | Fetch all Okta users |
| GET | /api/okta/users/mfa | Fetch users with MFA factors |
| POST | /api/okta/suspend/{userId} | Suspend a specific user |
| GET | /api/alerts | Run full scan + return alerts |

## Risk Detection Rules

| Risk Type | Description | Detection Logic | Severity |
|-----------|-------------|-----------------|----------|
| UNUSUAL_GEO_LOGIN | Login from unapproved country | Successful login from outside India/USA | MEDIUM |
| OUTSIDE_BUSINESS_HOURS | Login outside office hours | Success login before 09:00 or after 18:00 IST | LOW |
| BRUTE_FORCE_PATTERN | Possible brute-force attack | 3+ failures followed by success within 5 minutes | HIGH |
| NO_MFA_ENROLLED | User has no MFA factors | User has 0 MFA methods | HIGH |
| WEAK_MFA_ONLY | Only weak MFA factors | All MFA factors belong to weak list | MEDIUM |


