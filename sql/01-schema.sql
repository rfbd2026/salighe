-- در Supabase: SQL Editor > New query > اجرا (Run)

create table if not exists public.responses (
  id          uuid primary key default gen_random_uuid(),
  created_at  timestamptz not null default now(),
  first_name  text not null check (char_length(first_name) between 1 and 60),
  last_name   text not null check (char_length(last_name)  between 1 and 60),
  age_range   text not null check (char_length(age_range)  between 1 and 30),
  phone       text check (phone is null or char_length(phone) <= 20),
  answers     jsonb not null check (jsonb_typeof(answers) = 'array' and jsonb_array_length(answers) = 10),
  comment     text check (comment is null or char_length(comment) <= 600),
  my_ref      text not null check (char_length(my_ref) between 1 and 12),
  invited_by  text check (invited_by is null or char_length(invited_by) <= 12)
);

create index if not exists responses_invited_by_idx on public.responses (invited_by);

-- امنیت: فقط اجازه‌ی ثبت (insert)؛ هیچ‌کس از بیرون نمی‌تونه داده‌ها رو بخونه
alter table public.responses enable row level security;

drop policy if exists "anon can insert" on public.responses;
create policy "anon can insert"
  on public.responses for insert
  to anon
  with check (true);

-- (اختیاری) تعداد دعوت‌های موفق هر نفر، برای محاسبه‌ی تخفیف ۱۵٪
create or replace view public.referral_counts as
select invited_by as ref, count(*) as invited_count
from public.responses
where invited_by is not null
group by invited_by;
