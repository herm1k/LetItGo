# LetItGo

```text
                 .     *       .
       *        .     .        *
    .       _____________
         . /  LET IT GO /|
  *       /____________ / |
         |  expired    |  |
     .   |  domains    |  |
         |  can go     |  /
  *      |_____________|/

        release stale trust
```

**LetItGo** is a Python tool for checking **one thing only**:  
whether a registrable domain is **active**, **expiring soon**, **expired**, or **unknown**.

It is meant for **domain expiry hygiene**.

## What it does

LetItGo takes a list of domains or hostnames, normalizes them to registrable public domains, deduplicates them, and checks their apparent expiration date using:

- **RDAP** first
- **WHOIS** as a fallback

It then classifies each domain as:

- `active`
- `expiring_soon`
- `expired`
- `unknown`
- `not_registrable`

## Why

Domains often stay in inventories long after ownership becomes unclear.

That creates risk even when there is no direct takeover path:
- expired domains can be forgotten and later re-registered
- expiring domains can be missed during renewals
- stale hostnames create bad assumptions in inventories and reviews
- teams lose visibility into what is still owned and what is not

LetItGo helps answer a simple question:

> Which domains should we review right now because of expiration status?

## Scope

LetItGo is intentionally narrow.

It does **not**:
- detect dangling CNAMEs
- prove subdomain takeover
- validate Azure resource ownership
- delete DNS records

Those are separate problems and should stay in separate tools.

## Usage

Install dependencies:

```bash
pip install -r requirements.txt
```

Check a text file:

```bash
python letitgo.py --from-file sample_domains.txt --output results.csv
```

Check a CSV file:

```bash
python letitgo.py --from-file sample_domains.csv --csv-column domain --output results.csv
```

Mark anything within 45 days as `expiring_soon`:

```bash
python letitgo.py --from-file sample_domains.txt --warn-days 45 --output results.csv
```

Optional JSON output:

```bash
python letitgo.py --from-file sample_domains.txt --output results.csv --json-output results.json
```

## Input examples

`sample_domains.txt`
```text
example.com
app.example.org
docs.example.net
```

`sample_domains.csv`
```csv
domain
example.com
app.example.org
docs.example.net
```

## Output

The CSV report contains:

- `source`
- `input_name`
- `registrable_domain`
- `expiry_date`
- `days_left`
- `status`
- `notes`

## Notes

- RDAP and WHOIS coverage varies by TLD and registrar.
- Some domains may return incomplete or non-standard expiration data.
- `unknown` does not mean safe; it means the tool could not verify expiration reliably.
- Hostnames like `foo.azurewebsites.net` are usually not your registrable domain and may become `not_registrable` or normalize to a parent public suffix result depending on the input.

## License

 MIT.
