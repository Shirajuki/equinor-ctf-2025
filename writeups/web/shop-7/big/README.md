# Writeup: Shop-7
## Team: big🔥
**Author:** SpaceyLad (Stian Kvålshagen)

As usual, we use Burp for this!

The vulnerability here is that the object sent in the POST request can contain more variables than what is shown. So here you can simply inject _Customer__cash (Which we will explore more in the code analysis) to set a new int value when creating a new account.

When making a user, capture the register request and add the following payload:

```
{
"name": "admin",
"password": "admin",
"_Customer__cash": 999999
}
```

This replaces the innitial cash value with a new one.

Confirm that you have enough money and… Buy the flag :D

But why does this work?

## Code analysis

```
@app.route("/register", methods=["POST"])
def register():
    data = request.json
    customer = Customer()
    for key, value in data.items():
        setattr(customer, key, value)
    shop_manager.add_customer(customer)
    response = redirect("/")
    response.set_cookie("token", customer.get_token())
    return response
```

**setattr** is vulnerable here, as it will set a new value for the customer class.

```
class Customer:
    id: str
    name: str
    password: str
    __token: str
    __cash: int = 137
```

Which means that when it creates a user, it sets the default values, then it uses the given values by the customer, which will replace the already set values. Which in our case, is the __cash :D