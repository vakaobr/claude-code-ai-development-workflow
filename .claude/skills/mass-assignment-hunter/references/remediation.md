# remediation — mass-assignment-hunter

**Source:** `pentest-agent-development/notebooklm-notes/Guia de Segurança_ HPP e Mass Assignment em APIs.md` (Section 8: REMEDIATION)

---

## 1. Always Use an Explicit Allowlist

The root cause of Mass Assignment is binding "the whole request body" to
an internal model. Never do that. Accept a narrow, explicitly-defined
DTO / schema that mirrors ONLY the fields users are allowed to change.

### Django REST Framework

```python
# WRONG — exposes ALL model fields, including is_staff, is_superuser
class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = "__all__"           # DANGEROUS

# RIGHT — explicit allowlist
class UserUpdateSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ["first_name", "last_name", "email", "bio"]
        read_only_fields = ["email"]        # email is display-only
```

Never use `fields = "__all__"` on any serializer that accepts writes.

### Ruby on Rails — Strong Parameters

```ruby
class UsersController < ApplicationController
  def update
    # WRONG — permits everything
    # @user.update(params[:user])

    # RIGHT
    @user.update(user_params)
  end

  private
  def user_params
    params.require(:user).permit(:first_name, :last_name, :email, :bio)
    # NOT :admin, NOT :is_staff, NOT :role
  end
end
```

### Laravel

```php
// Model
class User extends Model
{
    // WRONG — $guarded = []; exposes everything
    // RIGHT — either:
    protected $fillable = ['first_name', 'last_name', 'email', 'bio'];
    // OR:
    protected $guarded = ['id', 'is_admin', 'role', 'created_at'];
}

// Controller
public function update(Request $req, User $user)
{
    $data = $req->validate([
        'first_name' => 'string|max:100',
        'email'      => 'email|unique:users,email,' . $user->id,
        // NOT 'is_admin'
    ]);
    $user->update($data);
    return response()->json($user);
}
```

### Spring Boot — DTO Pattern

```java
// DTO — narrow, no admin fields
public record UserUpdateDto(
    @NotBlank String firstName,
    @NotBlank String lastName,
    @Email    String email
) {}

@PutMapping("/users/{id}")
public User update(@PathVariable Long id,
                   @Valid @RequestBody UserUpdateDto dto) {
    User u = userRepo.findById(id).orElseThrow();
    u.setFirstName(dto.firstName());
    u.setLastName(dto.lastName());
    u.setEmail(dto.email());
    // never: u.setRole(anything)
    return userRepo.save(u);
}
```

Do NOT do `@RequestBody User user` — that binds the whole entity
including security-sensitive fields.

### Node.js / Express (TypeScript + zod)

```typescript
import { z } from "zod";

const UserUpdateSchema = z.object({
  firstName: z.string().max(100),
  lastName:  z.string().max(100),
  email:     z.string().email(),
  // NOT isAdmin, NOT role
});

app.put("/api/users/:id", async (req, res) => {
  const parsed = UserUpdateSchema.safeParse(req.body);
  if (!parsed.success) return res.status(400).json(parsed.error);
  await User.update({ _id: req.params.id }, parsed.data);
  res.status(200).end();
});
```

### NestJS

```typescript
export class UpdateUserDto {
  @IsString() @MaxLength(100) firstName: string;
  @IsString() @MaxLength(100) lastName: string;
  @IsEmail() email: string;
}

// Global ValidationPipe with whitelist + forbidNonWhitelisted
app.useGlobalPipes(new ValidationPipe({
  whitelist: true,
  forbidNonWhitelisted: true,  // rejects extra properties
}));
```

### ASP.NET Core

```csharp
public class UserUpdateDto
{
    [Required, MaxLength(100)] public string FirstName { get; set; }
    [Required, MaxLength(100)] public string LastName  { get; set; }
    [EmailAddress]             public string Email     { get; set; }
    // NO Role, NO IsAdmin
}

[HttpPut("{id}")]
public async Task<IActionResult> Update(int id, [FromBody] UserUpdateDto dto)
{
    if (!ModelState.IsValid) return BadRequest(ModelState);
    // map only the fields in dto to the entity
}
```

---

## 2. Prevent HTTP Parameter Pollution (HPP)

### Express — `hpp` middleware

```javascript
import hpp from "hpp";
app.use(hpp({ whitelist: ["tag"] }));   // tag may appear multiple times
```

### Node.js — manual query-string parsing

```javascript
// Accept only the first occurrence
const userId = Array.isArray(req.query.user_id)
    ? req.query.user_id[0]
    : req.query.user_id;
```

### Spring Boot — `@RequestParam` takes the first by default; for
`@RequestParam List<String>` pass an explicit filter step.

### Laravel

Laravel's `$request->input('user_id')` returns the last occurrence by
default. Explicitly check:

```php
$ids = $request->query('user_id');
if (is_array($ids) && count($ids) > 1) {
    abort(400, "duplicate parameter");
}
```

---

## 3. Separate Read Models from Write Models

Never put privilege-sensitive fields on the DTO that accepts writes,
even if they're read elsewhere:

```typescript
// READ model (what the client sees in GET responses)
class UserView {
  id: string;
  firstName: string;
  email: string;
  isAdmin: boolean;        // visible but NOT writable
  createdAt: Date;
}

// WRITE model (what a user's PUT may contain)
class UserUpdate {
  firstName?: string;
  email?: string;
  // nothing else
}
```

This "CQRS lite" split is the most effective architectural defense.

---

## 4. Schema-Based Validation + `forbidNonWhitelisted`

Reject — don't silently ignore — properties not in the allowlist. Silent
ignore masks genuine bugs and lets attackers probe for which properties
ARE honoured.

### NestJS

```typescript
new ValidationPipe({ forbidNonWhitelisted: true })
```

### Pydantic (FastAPI)

```python
from pydantic import BaseModel, Extra

class UserUpdate(BaseModel):
    first_name: str
    email: str
    model_config = {"extra": "forbid"}          # pydantic v2
    # pydantic v1: class Config: extra = Extra.forbid
```

### Ajv (Node)

```javascript
const ajv = new Ajv({ strict: true, additionalProperties: false });
```

---

## 5. Disable Path-Based Parameter Passing (PHP)

```ini
; php.ini
allow_url_include = Off
; PATH_INFO rarely needed — disable via framework router rather than server
```

---

## 6. Administrative Fields Require a Separate Endpoint + Separate Auth

- User-editing endpoint: `/api/users/me` — accepts `firstName`, `email`.
- Admin-editing endpoint: `/api/admin/users/{id}` — accepts `role`,
  `is_admin`, requires admin role.

Never have ONE endpoint that selectively honours fields based on the
caller's role — it's error-prone and a single missed check = escalation.

---

## 7. Audit Logging for Privilege-Sensitive Fields

Every change to `role`, `is_admin`, `balance`, etc., must log the
actor + timestamp. An attacker who finds a mass-assignment hole will
trip this monitoring.

```python
logger.info("privilege_change", extra={
    "event": "user_role_changed",
    "actor_id": actor.id,
    "target_user_id": target.id,
    "old_role": old_role,
    "new_role": new_role,
})
```

---

## Framework Quick-Reference

| Stack          | Canonical "don't bind everything" primitive                                 |
|----------------|-----------------------------------------------------------------------------|
| Django REST    | Serializer `fields = [...]` explicit + `read_only_fields`                   |
| Rails          | Strong Parameters (`params.require(...).permit(...)`)                       |
| Laravel        | `$fillable = [...]` OR request `validate()` with narrow schema              |
| Spring Boot    | DTO + `@Valid @RequestBody Dto`; never bind entities directly               |
| FastAPI        | Pydantic model with `extra = "forbid"`                                      |
| Express        | `zod` / `joi` / `ajv` schema parse then use parsed result only              |
| NestJS         | DTO + `ValidationPipe({ whitelist: true, forbidNonWhitelisted: true })`     |
| ASP.NET Core   | Dedicated input DTO class; never bind to EF entity directly                 |
| Go + gorm      | Use `model.Updates(map[string]interface{}{...})` with explicit keys         |

---

## 8. Regression Tests

```python
def test_mass_assignment_cannot_escalate(alice_client):
    r = alice_client.put(
        "/api/users/me",
        json={"first_name": "Alice", "is_admin": True, "role": "admin"},
    )
    assert r.status_code in (200, 400)
    me = alice_client.get("/api/users/me").json()
    assert me["is_admin"] is False
    assert me["role"] != "admin"

def test_hpp_rejected(client):
    r = client.get("/api/search?q=foo&q=bar")
    # Either both values concatenated into an array handled safely,
    # or a 400. Not a silent take-first-or-last based on internals.
    assert r.status_code == 200
    assert "internal_error" not in r.text
```
