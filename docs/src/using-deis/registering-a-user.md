# Registering a User

To use Deis, you must first register a user on the [Controller][].


## Register with a Controller

Use `deis register` with the [Controller][] URL (supplied by your Deis administrator)
to create a new account.  You will be logged in automatically.

The domain you use here should match the one you set with `deisctl config platform set domain=`.
Note that you always use `deis.<domain>` to communicate with the controller.

    $ deis register http://deis.example.com
    username: myuser
    password:
    password (confirm):
    email: myuser@example.com
    Registered myuser
    Logged in as myuser

!!! note
    For Vagrant clusters: `deis register http://deis.local3.deisapp.com`

!!! note
    The subdomain can be customized by using `deisctl config controller set subdomain=foo`. The
    router will then route requests from `foo.<domain>` to the controller.

!!! important
    The first user to register with Deis receives "superuser" privileges. Additional users who
    register will be ordinary users. It's also possible to disable user registration after creating
    the superuser account.


## Upload Your SSH Public Key

If you plan on using `git push` to deploy applications to Deis, you must provide your SSH public key.  Use the `deis keys:add` command to upload your default SSH public key, usually one of:

* ~/.ssh/id_rsa.pub
* ~/.ssh/id_dsa.pub

```
$ deis keys:add
Found the following SSH public keys:
1) id_rsa.pub
Which would you like to use with Deis? 1
Uploading /Users/myuser/.ssh/id_rsa.pub to Deis... done
```


## Logout from a Controller

Logout of an existing controller session using `deis logout`.

    $ deis logout
    Logged out as deis


## Login to a Controller

If you already have an account, use `deis login` to authenticate against the Deis [Controller][].

    $ deis login http://deis.example.com
    username: deis
    password:
    Logged in as deis

!!! note
    For Vagrant clusters: `deis login http://deis.local3.deisapp.com`

!!! note
    Deis session information is stored in your user's ~/.deis directory.


[controller]: ../understanding-deis/components.md#controller
