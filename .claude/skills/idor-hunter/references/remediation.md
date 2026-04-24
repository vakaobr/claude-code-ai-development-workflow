# remediation — idor-hunter

**Source:** `pentest-agent-development/notebooklm-notes/Guia Completo de Testes e Mitigação de IDOR.md` (Section 8: REMEDIATION)

---

## 1. Context-Aware Authorization on Every Resource Access

The fundamental fix: every request that references a specific object ID
must verify that the session's user is permitted to act on that specific
object.

### The "who is asking + what do they want + do they have rights" pattern

```python
# Django — explicit ownership check
def get_order(request, order_id):
    order = get_object_or_404(Order, id=order_id)
    if order.user_id != request.user.id and not request.user.is_staff:
        return HttpResponseForbidden()
    return render(request, "order.html", {"order": order})
```

```python
# Django — scoped queryset (CAN'T return someone else's record)
def get_order(request, order_id):
    order = get_object_or_404(Order, id=order_id, user=request.user)
    return render(request, "order.html", {"order": order})
```

The second pattern is safer because the filter is baked into the query —
there is no code path that returns the row before the check.

---

## 2. Framework-Specific Patterns

### Django REST Framework — per-object permissions

```python
from rest_framework.permissions import BasePermission

class IsOwner(BasePermission):
    def has_object_permission(self, request, view, obj):
        return obj.user_id == request.user.id

class OrderViewSet(viewsets.ModelViewSet):
    permission_classes = [IsAuthenticated, IsOwner]
    serializer_class  = OrderSerializer

    def get_queryset(self):
        # Always scope to current user — never return other users' rows
        return Order.objects.filter(user=self.request.user)
```

### Spring Security — `@PreAuthorize` + SpEL

```java
@Service
public class OrderService {

    @PreAuthorize("@orderSecurity.isOwner(#orderId, authentication)")
    public Order getOrder(Long orderId) {
        return orderRepository.findById(orderId).orElseThrow();
    }
}

@Component("orderSecurity")
public class OrderSecurity {
    public boolean isOwner(Long orderId, Authentication auth) {
        return orderRepository.existsByIdAndUsername(orderId, auth.getName());
    }
}
```

### Laravel — Policies

```php
// app/Policies/OrderPolicy.php
class OrderPolicy {
    public function view(User $user, Order $order) {
        return $user->id === $order->user_id;
    }
}

// Controller
public function show(Order $order) {
    $this->authorize('view', $order);        // throws 403 if not owner
    return response()->json($order);
}
```

### Express + `casl.js`

```javascript
import { defineAbility } from "@casl/ability";

function abilityFor(user) {
  return defineAbility((can) => {
    can("read", "Order", { userId: user.id });
    if (user.isAdmin) can("manage", "all");
  });
}

app.get("/api/orders/:id", requireAuth, async (req, res) => {
  const order = await Order.findById(req.params.id);
  if (!order) return res.status(404).end();
  if (abilityFor(req.user).cannot("read", order)) return res.status(403).end();
  res.json(order);
});
```

### FastAPI — dependency-injected authorization

```python
async def get_owned_order(
    order_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> Order:
    order = db.query(Order).filter_by(id=order_id, user_id=current_user.id).first()
    if not order:
        raise HTTPException(status_code=404)
    return order

@router.get("/orders/{order_id}")
async def read_order(order: Order = Depends(get_owned_order)):
    return order
```

### Go + gorm

```go
func getOrder(c *gin.Context) {
    userID := c.MustGet("user_id").(uint)
    orderID := c.Param("id")

    var order Order
    err := db.Where("id = ? AND user_id = ?", orderID, userID).First(&order).Error
    if err != nil {
        c.Status(http.StatusNotFound)
        return
    }
    c.JSON(200, order)
}
```

---

## 3. Use Non-Enumerable Identifiers (Defense in Depth)

Replace sequential integers with UUIDv4 or other high-entropy opaque IDs.
This is NOT a substitute for authorization — it raises the discovery cost,
it doesn't eliminate the bug.

### PostgreSQL

```sql
CREATE TABLE orders (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL,
    ...
);
```

### Django

```python
import uuid
class Order(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
```

### Rails

```ruby
create_table :orders, id: :uuid do |t|
  t.uuid :user_id, null: false
  # ...
end
```

---

## 4. Consistent Authorization Across ALL HTTP Methods

When GET is protected but DELETE isn't, attackers find the gap. Enforce
auth at the routing / middleware layer, not in each handler:

```python
# Django urls.py — one guard for the whole viewset
router.register(
    r"orders",
    OrderViewSet,          # all CRUD methods share IsOwner permission
    basename="orders",
)
```

```yaml
# API Gateway / Envoy — require the same policy for every verb
# Don't have "paths: /orders/{id}: get: auth: yes, post: auth: no"
```

Lint check: assert that every DELETE / PUT / PATCH route has an
`@authorize` decorator in CI.

---

## 5. Logging and Anomaly Detection

Log every 403 with user_id + resource_id + timestamp. Alert when:
- One user hits >N 403s in a minute (enumeration signal)
- Many users hit 403 on the same resource pattern (widespread scanning)

```python
# Structured log
logger.warning("unauthorized_access", extra={
    "event": "idor_attempt",
    "user_id": request.user.id,
    "resource_type": "order",
    "resource_id": resource_id,
    "path": request.path,
    "ip": request.META.get("REMOTE_ADDR"),
})
```

---

## 6. Bulk Endpoints — Per-Item Check

```python
# BAD — trusts the supplied list
def bulk_export(request):
    ids = request.data["order_ids"]
    orders = Order.objects.filter(id__in=ids)
    return JsonResponse([serialize(o) for o in orders])

# GOOD — scope to the user
def bulk_export(request):
    ids = request.data["order_ids"]
    orders = Order.objects.filter(id__in=ids, user=request.user)
    # If len(orders) != len(ids), the user asked for orders they don't own
    return JsonResponse([serialize(o) for o in orders])
```

---

## Framework Quick-Reference

| Stack                 | Canonical authorization primitive                                                    |
|-----------------------|--------------------------------------------------------------------------------------|
| Django                | Scoped `get_queryset`, custom `UserPassesTestMixin`, DRF object permissions          |
| Spring Security       | `@PreAuthorize("hasRole('ADMIN') or #id == authentication.principal.id")`            |
| Laravel               | Policies + `$this->authorize('view', $model)`                                        |
| Ruby on Rails         | `pundit` or `cancancan` gems; `authorize @order`                                     |
| Express / Node        | `casl.js`, `express-jwt-authz`, `@nestjs/casl`                                       |
| FastAPI               | Dependency-injected `Depends(get_current_owner)`                                     |
| ASP.NET Core          | `IAuthorizationService.AuthorizeAsync(user, resource, "OwnerPolicy")`                |
| Go / Gin              | Scoped DB queries + middleware extracting `userID` from JWT                          |
| GraphQL               | Field-level resolvers that verify ownership before returning; libraries like `graphql-shield` |

---

## 7. Regression Tests

```python
def test_alice_cannot_read_bobs_order(alice_client, bob_order):
    r = alice_client.get(f"/api/orders/{bob_order.id}")
    assert r.status_code in (403, 404)    # 404 is acceptable (non-discovery)

def test_alice_cannot_delete_bobs_order(alice_client, bob_order):
    r = alice_client.delete(f"/api/orders/{bob_order.id}")
    assert r.status_code in (403, 404)
    # Verify the record still exists
    assert Order.objects.filter(id=bob_order.id).exists()

def test_bulk_export_scopes_to_owner(alice_client, alice_order, bob_order):
    r = alice_client.post(
        "/api/orders/bulk-export",
        json={"order_ids": [alice_order.id, bob_order.id]},
    )
    returned_ids = {o["id"] for o in r.json()}
    assert bob_order.id not in returned_ids
```
