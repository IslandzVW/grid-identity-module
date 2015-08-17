var mysql = require('mysql');
var config = require('../config');
var md5 = require('MD5');

var IWGridUser = function(uuid, userName, em) {
    this.UUID = uuid;
    this.username = userName;
    this.email = em;
}

IWGridUser.mapUserQuery = function(sql, params, callback) {
    var connection = mysql.createConnection(config.iwGridDatabaseOptions);

    connection.connect(function(err) {
        if (err) {
            console.error('error connecting: ' + err.stack);
            callback(err, null);
            return;
        }

        connection.query(sql, params,
            function(err, results) {
                if (err) {
                    connection.end();
                    callback(err, null);
                    return;
                }

                var ret = {};
                for (var i = 0, len = results.length; i < len; i++) {
                    var result = results[i];

                    ret[result.UUID] = new IWGridUser(result.UUID,
                        result.username + " " + result.lastname, result.email);
                }

                connection.end();

                callback(null, ret);
            }
        );
    });
}

/**
 * Given a list of user IDs, returns a list of User objects
 */
IWGridUser.resolveUsers = function(userList, callback) {
    if (userList.length == 0) {
        callback(null, {});
        return;
    }

    IWGridUser.mapUserQuery(
        'SELECT UUID, username, lastname, email FROM users WHERE UUID IN (?);',
        [userList], callback);
}

IWGridUser.resolveUser = function(userId, callback) {
    var userList = [userId];
    IWGridUser.resolveUsers(userList, function(err, users) {
        if (err) {
            callback(err);
            return;
        }

        var keys = Object.keys(users);
        if (keys.length == 0) {
            callback(null, null);
        } else {
            callback(null, users[keys[0]]);
        }
    });
}

var IWGridIdentity = function() {
}

IWGridIdentity.authenticate = function(username, password, callback) {
    var firstLast = username.split(" ");
    if (firstLast.length != 2) {
        //we can't look up this user. it is not an IW user
        callback(null, false);
        return;
    }
    
    var connection = mysql.createConnection(config.iwGridDatabaseOptions);

    connection.connect(function(err) {
        if (err) {
            console.error('error connecting: ' + err.stack);
            callback(err);
            return;
        }

        connection.query(
            'SELECT UUID, username, lastname, email, passwordHash, passwordSalt ' +
                'FROM users WHERE username = ? AND lastname = ?;',
            [firstLast[0], firstLast[1]],
            function(err, result) {
                if (err) {
                    connection.end();
                    callback(err);
                    return;
                }

                //verify the user
                result = result[0];
                var fullHash = md5(md5(password) + ":" + result.passwordSalt);
                if (fullHash == result.passwordHash) {
                    callback(null, new IWGridUser(result.UUID,
                        result.username + " " + result.lastname, result.email));

                } else {
                    callback(null, false);
                }

                connection.end();
            }
        );

    });
}

IWGridIdentity.findUserByName = function(username, callback) {
    var firstLast = username.split(" ");
    if (firstLast.length != 2) {
        //we can't look up this user. it is not an IW user
        callback(null, null);
        return;
    }

    IWGridUser.mapUserQuery(
        'SELECT UUID, username, lastname, email FROM users WHERE username = ? ' +
            'AND lastname = ?;',
        [firstLast[0], firstLast[1]],
        function(err, users) {
            var keys = Object.keys(users);
            if (keys.length == 0) {
                callback(null, null);
            } else {
                callback(null, users[keys[0]]);
            }
        }
    );
}

IWGridIdentity.findUserById = function(userId, callback) {
    IWGridUser.resolveUser(userId, callback);
}

IWGridIdentity.findUsersById = function(userIdList, callback) {
    IWGridUser.resolveUsers(userIdList, callback);
}

module.exports = IWGridIdentity;
