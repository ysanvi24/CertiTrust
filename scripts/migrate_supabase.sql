-- Supabase SQL: documents & attestations

create table if not exists documents (
  id uuid default uuid_generate_v4() primary key,
  owner text,
  file_name text,
  file_hash text,
  created_at timestamptz default now()
);

create table if not exists attestations (
  id uuid default uuid_generate_v4() primary key,
  document_id uuid references documents(id) on delete cascade,
  tx_hash text,
  block_number integer,
  contract_address text,
  created_at timestamptz default now()
);

drop table if exists audit_logs;
create table audit_logs (
  id uuid default uuid_generate_v4() primary key,
  document_hash text not null,
  previous_hash text,
  issuance_date timestamptz default now()
);
