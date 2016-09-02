drop table if exists users;
create table users (
	user_id integer primary key autoincrement,
	username text not null,
	email text not null,
	pw_hash text not null
);

drop table if exists entries;
create table entries (
  id integer primary key autoincrement,
  author text not null,
  title text not null,
  'text' text not null
);