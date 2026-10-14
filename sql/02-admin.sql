-- بعد از schema.sql اجرا کن (SQL Editor > New query > Run)

-- ۱) ستون‌های جدید برای اطلاعات دستگاه
alter table public.responses
  add column if not exists user_agent       text,
  add column if not exists device           jsonb,
  add column if not exists ip               text,
  add column if not exists country          text,
  add column if not exists duration_seconds int;

alter table public.responses
  drop constraint if exists responses_meta_limits;
alter table public.responses
  add constraint responses_meta_limits check (
    (user_agent is null or char_length(user_agent) <= 500)
    and (device is null or octet_length(device::text) <= 4000)
    and (duration_seconds is null or duration_seconds between 0 and 86400)
  );

-- ۲) IP و کشور را سمت سرور از هدرهای درخواست می‌گیریم (کاربر نمی‌تونه جعلش کنه)
create or replace function public.set_request_meta()
returns trigger language plpgsql security definer set search_path = public as $$
declare h json;
begin
  new.ip := null;
  new.country := null;
  begin
    h := current_setting('request.headers', true)::json;
  exception when others then
    h := null;
  end;
  if h is not null then
    new.ip := nullif(trim(split_part(coalesce(h->>'cf-connecting-ip', h->>'x-forwarded-for', ''), ',', 1)), '');
    new.country := nullif(h->>'cf-ipcountry', '');
  end if;
  return new;
end $$;

drop trigger if exists responses_set_meta on public.responses;
create trigger responses_set_meta
  before insert on public.responses
  for each row execute function public.set_request_meta();

-- ۳) فهرست ادمین‌ها: ایمیل خودت را اینجا بذار
create table if not exists public.admins (email text primary key);
alter table public.admins enable row level security;   -- بدون policy: از بیرون قابل دسترس نیست

insert into public.admins (email) values ('YOUR-EMAIL@example.com')
on conflict do nothing;

create or replace function public.is_admin()
returns boolean language sql stable security definer set search_path = public as $$
  select exists (
    select 1 from public.admins
    where lower(email) = lower(coalesce(auth.jwt() ->> 'email', ''))
  )
$$;
revoke all on function public.is_admin() from public, anon;
grant execute on function public.is_admin() to authenticated;

-- ۴) فقط ادمین می‌تونه بخونه و حذف کنه
drop policy if exists "admin can read"   on public.responses;
drop policy if exists "admin can delete" on public.responses;
create policy "admin can read"   on public.responses for select to authenticated using (public.is_admin());
create policy "admin can delete" on public.responses for delete to authenticated using (public.is_admin());

-- ۵) ویوی تعداد دعوت‌ها را از دسترس عموم خارج می‌کنیم
alter view public.referral_counts set (security_invoker = true);
revoke all on public.referral_counts from anon;
grant select on public.referral_counts to authenticated;
