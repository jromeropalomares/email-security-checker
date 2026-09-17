import dns.resolver

class EmailSecurityChecker:
    def __init__(self, domain):
        self.domain = domain
        self.mx_records = []
        self.spf_record = None
        self.dmarc_record = None
        self.dkim_result = None

    def check_mx(self):
        try:
            self.mx_records = []

            records = dns.resolver.resolve(self.domain, "MX")

            for record in records:
                self.mx_records.append(str(record))

            return self.mx_records

        except dns.resolver.NXDOMAIN:
            print(f"The domain {self.domain} does not exist.")

        except dns.resolver.NoAnswer:
            print(f"No MX record found for {self.domain}.")

        except dns.resolver.LifetimeTimeout:
            print("The DNS lookup timed out.")

        except Exception as e:
            print(f"An error occurred: {e}")

    def check_spf(self):
        try:
            # Reset the value in case this method is called more than once
            self.spf_record = None

            records = dns.resolver.resolve(self.domain, "TXT")

            for record in records:
                text = record.to_text()

                if "v=spf1" in text:
                    self.spf_record = text
                    break

            return self.spf_record

        except dns.resolver.NXDOMAIN:
            print(f"The domain {self.domain} does not exist.")

        except dns.resolver.NoAnswer:
            print(f"No SPF record found for {self.domain}.")

        except dns.resolver.LifetimeTimeout:
            print("The DNS lookup timed out.")

        except Exception as e:
            print(f"An error occurred: {e}")

    def check_dmarc(self):
        try:
            self.dmarc_record = None

            records = dns.resolver.resolve(
                f"_dmarc.{self.domain}",
                "TXT"
            )

            for record in records:
                text = record.to_text()

                if "v=DMARC1" in text:
                    self.dmarc_record = text
                    break

            return self.dmarc_record

        except dns.resolver.NXDOMAIN:
            print(f"No DMARC record found for {self.domain}.")

        except dns.resolver.NoAnswer:
            print(f"No DMARC record found for {self.domain}.")

        except dns.resolver.LifetimeTimeout:
            print("The DNS lookup timed out.")

        except Exception as e:
            print(f"An error occurred: {e}")

    def check_dkim(self, selector):
        try:
            self.dkim_result = None

            records = dns.resolver.resolve(
                f"{selector}._domainkey.{self.domain}",
                "TXT"
            )

            for record in records:
                text = record.to_text()

                if "v=DKIM1" in text:
                    self.dkim_result = text
                    break

            return self.dkim_result

        except dns.resolver.NXDOMAIN:
            print(
                f"No DKIM record found for {self.domain} "
                f"using selector '{selector}'."
            )

        except dns.resolver.NoAnswer:
            print(
                f"No DKIM record found for {self.domain} "
                f"using selector '{selector}'."
            )

        except dns.resolver.LifetimeTimeout:
            print("The DNS lookup timed out.")

        except Exception as e:
            print(f"An error occurred: {e}")

    def generate_report(self, selector=None):
        self.check_mx()
        self.check_spf()
        self.check_dmarc()

        if selector is not None:
            self.check_dkim(selector)

        print("\nEmail Security Check")
        print("--------------------")
        print(f"Domain: {self.domain}")
        print(f"MX found: {self.mx_records}")
        print(f"SPF found: {self.spf_record}")
        print(f"DMARC found: {self.dmarc_record}")

        if selector is not None:
            print(f"DKIM found: {self.dkim_result}")


if __name__ == "__main__":
    domain = input("Enter domain: ").strip().lower()

    checker = EmailSecurityChecker(domain)

    checker.generate_report()
