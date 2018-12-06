<?php

/*
 * This file is part of the Symfony package.
 *
 * (c) Fabien Potencier <fabien@symfony.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Symfony\Component\Ldap\Tests;

use Symfony\Component\Ldap\Adapter\ExtLdap\Adapter;
use Symfony\Component\Ldap\Adapter\ExtLdap\Collection;
use Symfony\Component\Ldap\Adapter\ExtLdap\Query;
use Symfony\Component\Ldap\Entry;
use Symfony\Component\Ldap\Exception\NotBoundException;
use Symfony\Component\Ldap\LdapInterface;

/**
 * @requires extension ldap
 */
class AdapterTest extends LdapTestCase
{
    public function testLdapEscape()
    {
        $ldap = new Adapter();

        $this->assertEquals('\20foo\3dbar\0d(baz)*\20', $ldap->escape(" foo=bar\r(baz)* ", null, LdapInterface::ESCAPE_DN));
    }

    /**
     * @group functional
     */
    public function testLdapQuery()
    {
        $ldap = new Adapter($this->getLdapConfig());

        $ldap->getConnection()->bind('cn=admin,dc=symfony,dc=com', 'symfony');
        $query = $ldap->createQuery('dc=symfony,dc=com', '(&(objectclass=person)(ou=Maintainers))', array());
        $result = $query->execute();

        $this->assertInstanceOf(Collection::class, $result);
        $this->assertCount(1, $result);

        $entry = $result[0];
        $this->assertInstanceOf(Entry::class, $entry);
        $this->assertEquals(array('Fabien Potencier'), $entry->getAttribute('cn'));
        $this->assertEquals(array('fabpot@symfony.com', 'fabien@potencier.com'), $entry->getAttribute('mail'));
    }

    /**
     * @group functional
     */
    public function testLdapQueryIterator()
    {
        $ldap = new Adapter($this->getLdapConfig());

        $ldap->getConnection()->bind('cn=admin,dc=symfony,dc=com', 'symfony');
        $query = $ldap->createQuery('dc=symfony,dc=com', '(&(objectclass=person)(ou=Maintainers))', array());
        $result = $query->execute();
        $iterator = $result->getIterator();
        $iterator->rewind();
        $entry = $iterator->current();
        $this->assertInstanceOf(Entry::class, $entry);
        $this->assertEquals(array('Fabien Potencier'), $entry->getAttribute('cn'));
        $this->assertEquals(array('fabpot@symfony.com', 'fabien@potencier.com'), $entry->getAttribute('mail'));
    }

    /**
     * @group functional
     */
    public function testLdapQueryWithoutBind()
    {
        $ldap = new Adapter($this->getLdapConfig());
        $this->{method_exists($this, $_ = 'expectException') ? $_ : 'setExpectedException'}(NotBoundException::class);
        $query = $ldap->createQuery('dc=symfony,dc=com', '(&(objectclass=person)(ou=Maintainers))', array());
        $query->execute();
    }

    public function testLdapQueryScopeBase()
    {
        $ldap = new Adapter($this->getLdapConfig());

        $ldap->getConnection()->bind('cn=admin,dc=symfony,dc=com', 'symfony');

        $query = $ldap->createQuery('cn=Fabien Potencier,dc=symfony,dc=com', '(objectclass=*)', array(
           'scope' => Query::SCOPE_BASE,
        ));
        $result = $query->execute();

        $entry = $result[0];
        $this->assertEquals($result->count(), 1);
        $this->assertEquals(array('Fabien Potencier'), $entry->getAttribute('cn'));
    }

    public function testLdapQueryScopeOneLevel()
    {
        $ldap = new Adapter($this->getLdapConfig());

        $ldap->getConnection()->bind('cn=admin,dc=symfony,dc=com', 'symfony');

        $one_level_result = $ldap->createQuery('ou=Components,dc=symfony,dc=com', '(objectclass=*)', array(
            'scope' => Query::SCOPE_ONE,
        ))->execute();

        $subtree_count = $ldap->createQuery('ou=Components,dc=symfony,dc=com', '(objectclass=*)')->execute()->count();

        $this->assertNotEquals($one_level_result->count(), $subtree_count);
        $this->assertEquals($one_level_result->count(), 1);
        $this->assertEquals($one_level_result[0]->getAttribute('ou'), array('Ldap'));
    }

    public function testLdapPagination()
    {
        $ldap = new Adapter($this->getLdapConfig());

        $ldap->getConnection()->bind('cn=admin,dc=symfony,dc=com', 'symfony');

        // Create 25 'users' that we'll query for in different page sizes
        $em = $ldap->getEntryManager();
        for ($i = 0; $i < 25; ++$i) {
            $cn = sprintf('user%d', $i);
            $entry = new Entry(sprintf('cn=%s,dc=symfony,dc=com', $cn));
            $entry->setAttribute('objectClass', array('top', 'organizationalPerson'));
            $entry->setAttribute('cn', $cn);
            $em->add($entry);
        }

        $unpaged_query = $ldap->createQuery('dc=symfony,dc=com', '(&(objectClass=organizationalPerson)(cn=user*))', array(
            'scope' => Query::SCOPE_ONE,
        ));
        $fully_paged_query = $ldap->createQuery('dc=symfony,dc=com', '(&(objectClass=organizationalPerson)(cn=user*))', array(
            'scope' => Query::SCOPE_ONE,
            'pageSize' => 25,
        ));
        $paged_query = $ldap->createQuery('dc=symfony,dc=com', '(&(objectClass=organizationalPerson)(cn=user*))', array(
            'scope' => Query::SCOPE_ONE,
            'pageSize' => 5,
        ));

        // This last query is to ensure that we haven't botched the state of our connection by not resetting pagination properly
        $final_query = $ldap->createQuery('dc=symfony,dc=com', '(&(objectClass=organizationalPerson)(cn=user*))', array(
            'scope' => Query::SCOPE_ONE,
        ));

        $unpaged_results = $unpaged_query->execute();
        $fully_paged_results = $fully_paged_query->execute();
        $paged_results = $paged_query->execute();
        $final_results = $final_query->execute();

        // All four of the above queries should result in the 25 'users' being returned
        $this->assertEquals($unpaged_results->count(), 25);
        $this->assertEquals($fully_paged_results->count(), 25);
        $this->assertEquals($paged_results->count(), 25);
        $this->assertEquals($final_results->count(), 25);

        // They should also result in 1 or 25 / pageSize results
        $this->assertEquals(\count($unpaged_query->getResources()), 1);
        $this->assertEquals(\count($fully_paged_query->getResources()), 1);
        $this->assertEquals(\count($paged_query->getResources()), 5);
        $this->assertEquals(\count($final_query->getResources()), 1);
    }

    public function testLdapPagination()
    {
        $ldap = new Adapter($this->getLdapConfig());

        $ldap->getConnection()->bind('cn=admin,dc=symfony,dc=com', 'symfony');

        // Create 25 'users' that we'll query for in different page sizes
        $em = $ldap->getEntryManager();
        for ($i = 0; $i < 25; ++$i) {
            $cn = sprintf('user%d', $i);
            $entry = new Entry(sprintf('cn=%s,dc=symfony,dc=com', $cn));
            $entry->setAttribute('objectClass', array('top', 'organizationalPerson'));
            $entry->setAttribute('cn', $cn);
            $em->add($entry);
        }

        $low_max_query = $ldap->createQuery('dc=symfony,dc=com', '(&(objectClass=organizationalPerson)(cn=user*))', array(
            'scope' => Query::SCOPE_ONE,
            'pageSize' => 10,
            'maxItems' => 5,
        ));
        $high_max_query = $ldap->createQuery('dc=symfony,dc=com', '(&(objectClass=organizationalPerson)(cn=user*))', array(
            'scope' => Query::SCOPE_ONE,
            'pageSize' => 10,
            'maxItems' => 13,
        ));

        $low_max_results = $low_max_query->execute();
        $high_max_results = $high_max_query->execute();

        $this->assertEquals($low_max_results->count(), 5);
        $this->assertEquals($high_max_results->count(), 13);

        $this->assertEquals(\count($low_max_query->getResources()), 1);
        $this->assertEquals(\count($high_max_query->getResources()), 2);
    }
}
