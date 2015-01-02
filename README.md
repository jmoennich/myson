myson
=====

Prototype of an apache module that executes files as queries and returns the result as JSON

Example configuration
=====

In httpd.conf

    <Location /myson/db>
      SetHandler myson
      MysonDatabase testdb
    </Location>

* Now every file under `/myson/db` gets executed as MySQL query and its result is returned as JSON.
* A basic authentication for MySQL user is done for each request. 
* POST-Parameters are substituted like this:
  
<pre>SELECT * FROM users WHERE name='{username}'</pre>
