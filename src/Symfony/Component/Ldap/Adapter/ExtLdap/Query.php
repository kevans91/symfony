<?php

/*
 * This file is part of the Symfony package.
 *
 * (c) Fabien Potencier <fabien@symfony.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Symfony\Component\Ldap\Adapter\ExtLdap;

use Symfony\Component\Ldap\Adapter\AbstractQuery;
use Symfony\Component\Ldap\Exception\LdapException;
use Symfony\Component\Ldap\Exception\NotBoundException;

/**
 * @author Charles Sarrazin <charles@sarraz.in>
 * @author Bob van de Vijver <bobvandevijver@hotmail.com>
 */
class Query extends AbstractQuery
{
    const PAGINATION_OID = '1.2.840.113556.1.4.319';

    /** @var Connection */
    protected $connection;

    /** @var resource[] */
    private $results;

    public function __construct(Connection $connection, string $dn, string $query, array $options = array())
    {
        parent::__construct($connection, $dn, $query, $options);
    }

    public function __destruct()
    {
        $con = $this->connection->getResource();
        $this->connection = null;

        if (null === $this->results) {
            return;
        }

        foreach ($this->results as $result) {
            if (false === $result || null === $result) {
                continue;
            }
            if (!ldap_free_result($result)) {
                throw new LdapException(sprintf('Could not free results: %s.', ldap_error($con)));
            }
        }
        $this->results = null;
    }

    /**
     * {@inheritdoc}
     */
    public function execute()
    {
        if (null === $this->results) {
            // If the connection is not bound, throw an exception. Users should use an explicit bind call first.
            if (!$this->connection->isBound()) {
                throw new NotBoundException('Query execution is not possible without binding the connection first.');
            }

            $this->results = array();
            $con = $this->connection->getResource();

            switch ($this->options['scope']) {
                case static::SCOPE_BASE:
                    $func = 'ldap_read';
                    break;
                case static::SCOPE_ONE:
                    $func = 'ldap_list';
                    break;
                case static::SCOPE_SUB:
                    $func = 'ldap_search';
                    break;
                default:
                    throw new LdapException(sprintf('Could not search in scope "%s".', $this->options['scope']));
            }

            $maxItems = $this->options['maxItems'];
            $itemsLeft = $maxItems;
            $pageSize = $this->options['pageSize'];
            if (0 !== $maxItems && $pageSize > $maxItems) {
                $pageSize = 0;
            } elseif (0 !== $maxItems) {
                $pageSize = min($maxItems, $pageSize);
            }
            $pageControl = $this->options['scope'] != static::SCOPE_BASE && $pageSize > 0;
            $cookie = $lastCookie = '';

            do {
                if ($pageControl) {
					var_dump($pageSize);
                    ldap_control_paged_result($con, $pageSize, true, $cookie);
                }

                $sizeLimit = $itemsLeft;
                if ($sizeLimit >= $pageSize) {
                    $sizeLimit = 0;
                }
                $search = @$func(
                    $con,
                    $this->dn,
                    $this->query,
                    $this->options['filter'],
                    $this->options['attrsOnly'],
                    $sizeLimit,
                    $this->options['timeout'],
                    $this->options['deref']
                );

                if (false === $search) {
                    $ldapError = '';
                    if ($errno = ldap_errno($con)) {
                        $ldapError = sprintf(' LDAP error was [%d] %s', $errno, ldap_error($con));
                    }
                    if ($pageControl) {
                        $this->resetPagination();
                    }

                    throw new LdapException(sprintf('Could not complete search with dn "%s", query "%s" and filters "%s".%s', $this->dn, $this->query, implode(',', $this->options['filter']), $ldapError));
                }

                $this->results[] = $search;
                $itemsLeft -= min($itemsLeft, $pageSize);

                if (0 !== $maxItems && 0 === $itemsLeft) {
                    break;
                }
                if ($pageControl) {
                    ldap_control_paged_result_response($con, $search, $cookie);
                }
            } while (null !== $cookie && '' !== $cookie);

            if ($pageControl) {
                $this->resetPagination();
            }
        }

        return new Collection($this->connection, $this);
    }

    /**
     * Returns a LDAP search resource. If this query resulted in multiple searches, only the first
     * page will be returned.
     *
     * @return resource
     *
     * @internal
     */
    public function getResource($idx = 0)
    {
        if (null === $this->results || $idx >= \count($this->results)) {
            return null;
        } else {
            return $this->results[$idx];
        }
    }

    /**
     * Returns all LDAP search resources.
     *
     * @return resource[]
     *
     * @internal
     */
    public function getResources()
    {
        return $this->results;
    }

    /**
     * Resets pagination on the current connection.
     *
     * @internal
     */
    private function resetPagination()
    {
        $con = $this->connection->getResource();
        ldap_control_paged_result($con, 0);
        // This is a bit of a hack-around. The PHP LDAP extension should likely be
        // unsetting this OID when we send the above 0-sized page request. Not
        // unsetting this OID results in future non-paged requests failing silently
        // by returning 0 results or some subset of the actual results that should
        // have been returned.
        $ctl = array();
        ldap_get_option($con, LDAP_OPT_SERVER_CONTROLS, $ctl);
        if (!empty($ctl)) {
            foreach ($ctl as $idx => $info) {
                if (static::PAGINATION_OID == $info['oid']) {
                    unset($ctl[$idx]);
                }
            }
            ldap_set_option($con, LDAP_OPT_SERVER_CONTROLS, $ctl);
        }
    }
}
