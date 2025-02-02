## Overview

Key diversification ensures that each card receives a unique key value, enhancing security by limiting the impact of a compromised key to just that specific card, rather than affecting the entire system. During the card's personalization phase, these diversified keys are generated and stored on the card (PICC). When validating a card, the terminal uses the provided information to generate the unique key for that specific card.

The [NXP application note AN10922](https://www.nxp.com/docs/en/application-note/AN10922.pdf) provides an example algorithm
on how diversified keys should be generated, and this package provides an implementation of this for convenience.

## Usage

It is required to provide some diversification data, which is unique to the card that is being personalized.
Common practice is to use the real UID of the card, along with some other data such as the application ID(s) being
used or some other data.

Then, diversified keys can be created as follows:

```python
from desfire import diversify_key, get_list

BASE_KEY = "00112233445566778899AABBCCDDEEFF"
UID = "04782E21801D80"
APPID = "3042F5"
SYSID = "4E585020416275"

diversify_data = [0x01] + get_list(UID) + get_list(APPID) + get_list(SYSID)
div_key = diversify_key(get_list(BASE_KEY), diversify_data, pad_to_32=True)
```

You can use the result of the `diversify_key` function to construct a new `DESFireKey` object which
can then be used for authentication.
