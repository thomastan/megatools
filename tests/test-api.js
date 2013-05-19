/*
 *  megatools - Mega.co.nz client library and tools
 *  Copyright (C) 2013  Ondřej Jirman <megous@megous.com>
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License along
 *  with this program; if not, write to the Free Software Foundation, Inc.,
 *  51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

const Gio = imports.gi.Gio;
const GLib = imports.gi.GLib;
const Lang = imports.lang;
const Mega = imports.gi.Mega;
const Config = imports.config;

function each(arr, fn) {
	var i;
	for (i = 0; i < arr.length; i++) {
		fn(arr[i]);
	}
}

// load session

var s = new Mega.Session();
var fs = s.filesystem;

try {
	s.load(Config.USERNAME, Config.PASSWORD);
} catch(ex) {
	s.login(Config.USERNAME, Config.PASSWORD);
	fs.load();
	s.save();
}

// iterate over nodes

print("Iter:");
each(fs.get_root_nodes(), function(n) {
	print(n.path);
	each(n.get_children(), function(cn) {
		print("  -> " + cn.path);
	});
});

// glob match

print("Glob:");
each(fs.glob('/R*/B*/*/*full*'), function(n) {
	print(n.path);
});

// filter nodes

print("Filter:");
each(fs.filter_nodes(function(n) {
	return !!n.name.match(/sigtar/);
}), function(n) {
	print(n.path);
});
