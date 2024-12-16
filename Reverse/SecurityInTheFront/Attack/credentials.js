async function checkCredentials() {
    var access_user = document.getElementById("access-user").value;
    var access_code = document.getElementById("access-code").value;
    var c1 = "NOPQRSTUVWXYZABCDEFGHIJKLMnopqrstuvwxyzabcdefghijklm";
    var c2 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
    var n1 = [5, 6, 7, 8, 9, 0, 1, 2, 3, 4];
    var n2 = "0123456789";

    var n = (e, t, r) => e.reduce(((e, r, n) => r.apply(e, t[n])), r),
        h = function (e) {
            return this == e
        },
        f = function (e) {
            return indexedDB.cmp(this, e)
        }

    if ([
        [
            [String.prototype.split, Array.prototype.map, f, h],
            [[""], [e => -1 == Array.prototype.indexOf(c2, e) ? e : c1[Array.prototype.indexOf(c2, e)]],
            [
                ["n", "q", "z", "v", "a"]
            ],
            [0]
            ], access_user
        ], // admin
        [
            [String.prototype.slice, String.prototype.repeat, String.prototype.split, Array.prototype.map, Array.prototype.filter, f, h],
            [
                [0, 4],
                [3], [""], [e => -1 == Array.prototype.indexOf(c2, e) ? e : c1[Array.prototype.indexOf(c2, e)]],
                [(e, t) => t % 3 == 1], // HTB{HTB{HTB{
                [
                    ["G", "U", "{", "O"]
                ],
                [0]
            ], access_code
        ], // 0-4: HTB{
        [
            [String.prototype.slice, function () {
                return encodeURI(this)
            }, String.prototype.slice, function (e) {
                return parseInt(this, e)
            }, function (e) {
                return this ^ e
            }, h],
            [
                [-1],
                [],
                [-2],
                [16],
                [96],
                [29]
            ], access_code
        ], // Last char: }
        [
            [String.prototype.split, Array.prototype.reduce, h],
            [[""], [e => e + e, 1],
            [16777216]
            ], access_code
        ], // The sum of all characters + 1 is 16777216
        [
            [String.prototype.repeat, String.prototype.split, Array.prototype.map, Array.prototype.reduce, h],
            [
                [21], [""], [e => n1[Array.prototype.indexOf(n2, e)]],
                [(e, t) => e + h.apply(t, [8]), 0],
                [63]
            ], access_code
        ], // There are 3 characters "3" ??????
        [
            [String.prototype.split, Array.prototype.filter, Array.prototype.map, Array.prototype.reverse, Array.prototype.join, h],
            [[""], [(e, t) => ~Array.prototype.indexOf([4, 11, 13, 14, 16, 17, 20, 22], t)],
            [e => c1[Array.prototype.indexOf(c2, e)]], // FDPWCHKR
            [],
            ["-"], // SQCJPUXE
            ["E-X-U-P-J-C-Q-S"]
            ], access_code
        ], // ____F______D_PW_CH__K_R ??????
        [
            [function () {
                return Array.from(this)
            }, f, h],
            [
                [],
                [
                    ["_"]
                ],
                [0]
            ], new Set(n([String.prototype.slice, String.prototype.split, Array.prototype.reverse, Array.prototype.filter], [
                [12, 16], // Slice from 12 to 16
                [""], // Gets all letters
                [], // Reverse
                [(e, t) => ~Array.prototype.indexOf([0, 3], [t])] // Keep only index 0 and 3
            ], access_code)) // It's a set, so characters in positions 0 and 3 are the same
        ], // Positions 12 and 15 are "_"
        [
            [String.prototype.split, Array.prototype.reverse, Array.prototype.filter, function () {
                return this.slice(2, this.length).concat(this.slice(0, 2))
            }, Array.prototype.reverse, Array.prototype.join, h],
            [[""], [], // r_nt_n________c____
            [(e, t) => ~Array.prototype.indexOf([18, 13, 4, 16, 15], [t])], // ____c________n_tn_r
            [], // Puts two first elements to the end: cntnr
            [], // Reverse: tnrcn
            [""],
            ["ncrnt"]
            ], access_code
        ], // r_nt_n________c____
        [
            [String.prototype.charAt, h],
            [
                [6],
                ["0"]
            ], access_code
        ] // Position 6: 0
    ].reduce(((e, t) => e && n.apply(undefined, t)), true)) {
        var v = new Uint8Array((new TextEncoder).encode(access_code)),
            g = new Uint8Array(await crypto.subtle.digest("SHA-256", v)),
            m = new Uint8Array([9, 87, 39, 96, 151, 202, 140, 186, 120, 235, 167, 229, 47, 231, 6, 212, 77, 205, 58, 14, 248, 104, 169, 79, 116, 140, 236, 98, 126, 26, 100, 120]);
        0 == indexedDB.cmp(g, m) ? activate() : alert("User is not authorized. This incident will be reported.")
    } else alert("User is not authorized.")
}

/*
HTB{
----F------D-PW-CH--K-R-
-----r-nt-n--------c----
------0-----------------
------------_--_--------
}
HTB{Fr0nt3nD_PW_CH3cK3R}
*/