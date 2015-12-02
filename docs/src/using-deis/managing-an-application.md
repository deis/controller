# Managing an Application

Deis includes many tools for managing deployed [Applications][application].


## Scale the Application

Applications deployed on Deis [scale out via the process model][].
Use `deis scale` to control the number of [Containers][container] that power your app.

    $ deis scale web=8
    Scaling processes... but first, coffee!
    done in 20s

    === peachy-waxworks Processes

    --- web:
    web.1 up (v2)
    web.2 up (v2)
    web.3 up (v2)
    web.4 up (v2)
    web.5 up (v2)
    web.6 up (v2)
    web.7 up (v2)
    web.8 up (v2)

Scaling is managed by process types like `web` or `worker` defined in a
[Procfile][] in the root of your application repository.

!!! note
    Docker applications can use the `cmd` process type to scale the default container command.


## Administer the Application

Deis applications [use one-off processes for admin tasks][] like database migrations and other commands that must run against the live application.

Use `deis run` to execute commands on the deployed application.

    $ deis run 'ls -l'
    Running `ls -l`...

    total 28
    -rw-r--r-- 1 root root  553 Dec  2 23:59 LICENSE
    -rw-r--r-- 1 root root   60 Dec  2 23:59 Procfile
    -rw-r--r-- 1 root root   33 Dec  2 23:59 README.md
    -rw-r--r-- 1 root root 1622 Dec  2 23:59 pom.xml
    drwxr-xr-x 3 root root 4096 Dec  2 23:59 src
    -rw-r--r-- 1 root root   25 Dec  2 23:59 system.properties
    drwxr-xr-x 6 root root 4096 Dec  3 00:00 target


## Share the Application

Use `deis perms:create` to allow another Deis user to collaborate on your application.

    $ deis perms:create otheruser
    Adding otheruser to peachy-waxworks collaborators... done

Use `deis perms` to see who an application is currently shared with, and
`deis perms:remove` to remove a collaborator.

!!! note
    Collaborators can do anything with an application that its owner can do,
    except delete the application itself.

When working with an application that has been shared with you, clone the original repository and add Deis' git remote entry before attempting to `git push` any changes to Deis.

    $ git clone https://github.com/deis/example-java-jetty.git
    Cloning into 'example-java-jetty'... done
    $ cd example-java-jetty
    $ git remote add -f deis ssh://git@local3.deisapp.com:2222/peachy-waxworks.git
    Updating deis
    From deis-controller.local:peachy-waxworks
     * [new branch]      master     -> deis/master


## Troubleshoot the Application

Applications deployed on Deis [treat logs as event streams][]. Deis aggregates `stdout` and `stderr` from every [Container][] making it easy to troubleshoot problems with your application.

Use `deis logs` to view the log output from your deployed application.

    $ deis logs | tail
    Dec  3 00:30:31 ip-10-250-15-201 peachy-waxworks[web.5]: INFO:oejsh.ContextHandler:started o.e.j.s.ServletContextHandler{/,null}
    Dec  3 00:30:31 ip-10-250-15-201 peachy-waxworks[web.8]: INFO:oejs.Server:jetty-7.6.0.v20120127
    Dec  3 00:30:31 ip-10-250-15-201 peachy-waxworks[web.5]: INFO:oejs.AbstractConnector:Started SelectChannelConnector@0.0.0.0:10005
    Dec  3 00:30:31 ip-10-250-15-201 peachy-waxworks[web.6]: INFO:oejsh.ContextHandler:started o.e.j.s.ServletContextHandler{/,null}
    Dec  3 00:30:31 ip-10-250-15-201 peachy-waxworks[web.7]: INFO:oejsh.ContextHandler:started o.e.j.s.ServletContextHandler{/,null}
    Dec  3 00:30:31 ip-10-250-15-201 peachy-waxworks[web.6]: INFO:oejs.AbstractConnector:Started SelectChannelConnector@0.0.0.0:10006
    Dec  3 00:30:31 ip-10-250-15-201 peachy-waxworks[web.8]: INFO:oejsh.ContextHandler:started o.e.j.s.ServletContextHandler{/,null}
    Dec  3 00:30:31 ip-10-250-15-201 peachy-waxworks[web.7]: INFO:oejs.AbstractConnector:Started SelectChannelConnector@0.0.0.0:10007
    Dec  3 00:30:31 ip-10-250-15-201 peachy-waxworks[web.8]: INFO:oejs.AbstractConnector:Started SelectChannelConnector@0.0.0.0:10008


## Limit the Application

Deis supports restricting memory and CPU shares of each [Container][].

Use `deis limits:set` to restrict memory by process type:

    $ deis limits:set web=512M
    Applying limits... done, v3

    === peachy-waxworks Limits

    --- Memory
    web      512M

    --- CPU
    Unlimited

You can also use `deis limits:set -c` to restrict CPU shares.
CPU shares are on a scale of 0 to 1024, with 1024 being all CPU resources on the host.

!!! important
    If you restrict resources to the point where containers do not start,
    the `limits:set` command will hang.  If this happens, use CTRL-C
    to break out of `limits:set` and use `limits:unset` to revert.


## Isolate the Application

Deis supports isolating applications onto a set of hosts using `tags`.

!!! note
    In order to use tags, you must first launch your hosts with
    the proper key/value tag information.  If you do not, tag commands will fail.
    Learn more by reading the [machine metadata][] section of Fleet documentation.

Once your hosts are configured with appropriate key/value metadata, use
`deis tags:set` to restrict the application to those hosts:

    $ deis tags:set environ=prod
    Applying tags...  done, v4

    environ  prod

[application]: ../reference-guide/terms.md#application
[container]: ../reference-guide/terms.md#container
[store config in environment variables]: http://12factor.net/config
[decoupled from the application]: http://12factor.net/backing-services
[scale out via the process model]: http://12factor.net/concurrency
[treat logs as event streams]: http://12factor.net/logs
[use one-off processes for admin tasks]: http://12factor.net/admin-processes
[Procfile]: http://ddollar.github.io/foreman/#PROCFILE
[machine metadata]: https://coreos.com/docs/launching-containers/launching/fleet-unit-files/#user-defined-requirements
