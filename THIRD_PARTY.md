# Third-party source notices

This product includes PHP software, freely available from
<http://www.php.net/software/>.

This product includes the Zend Engine, freely available at
http://www.zend.com

The Zend Engine is freely available at http://www.zend.com

`mitigation.patch` and `version.patch` preserve commit metadata and source diffs
from [CalCyber PHP Security Backports](https://github.com/Calcyber-Security/php-security-backports).
The PHP 7.4 baseline is upstream commit
`dca8d5565b947270a29f232bc54efd9df3b92b94`.

- PHP source portions remain covered by [PHP License 3.01](licenses/PHP-3.01.txt).
- Zend Engine source portions remain covered by [Zend Engine License 2.00](licenses/Zend-2.00.txt).
- Existing source notices and individual file licenses remain authoritative.

The mitigation commit `16c7f82e9254eb50bf8fbc5412af5a41856db99b` credits
Arnaud Le Blanc and Ilija Tovilo and records the cherry-pick of upstream PHP
commit `712e60f9edfd03f0960fc4fc3c2c375f42b90aa2`. The version commit is
`51c83a94789563515a275a3f55dc52ca3cd867fd`; its original contributor metadata
is retained in the patch. Publishing these files does not claim authorship of
the upstream fixes or endorsement by the PHP Group or Zend Technologies.

The local Python runner, unit tests and PHP fixtures were independently authored
for this finite lab. The remote scanner and large multipart sweep from the
earlier test bundle are not included. No repository-wide license is imposed on
the upstream code by this notice.

License texts were retrieved from the pinned upstream source:

- https://github.com/php/php-src/blob/dca8d5565b947270a29f232bc54efd9df3b92b94/LICENSE
- https://github.com/php/php-src/blob/dca8d5565b947270a29f232bc54efd9df3b92b94/Zend/LICENSE
