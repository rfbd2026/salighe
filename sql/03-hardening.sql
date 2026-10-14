-- ===== سخت‌سازی امنیتی (بعد از 01 و 02 اجرا کن؛ چندبار اجرا کردنش مشکلی ندارد) =====

-- ۱) دسترسی‌ها را از صفر می‌بندیم و فقط حداقل لازم را باز می‌کنیم
revoke all on public.responses from anon, authenticated;
revoke all on public.admins    from anon, authenticated;

-- مهمان فقط می‌تواند این ستون‌ها را ثبت کند (id, زمان, ip, کشور را خود سرور پر می‌کند)
grant insert (first_name, last_name, age_range, phone, answers, comment,
              my_ref, invited_by, user_agent, device, duration_seconds)
  on public.responses to anon;

-- ادمین (بعد از لاگین) فقط خواندن و حذف
grant select, delete on public.responses to authenticated;

-- ۲) قوانین دقیق‌تر برای داده‌ی ورودی (روی ردیف‌های قدیمی اثر نمی‌ذارد)
alter table public.responses drop constraint if exists responses_strict;
alter table public.responses add constraint responses_strict check (
      age_range in ('زیر ۱۸', '۱۸ تا ۲۴', '۲۵ تا ۳۴', '۳۵ تا ۴۴', '۴۵ به بالا')
  and (phone is null or phone ~ '^[0-9۰-۹+[:space:]-]{7,16}$')
  and my_ref ~ '^[a-z0-9]{1,12}$'
  and (invited_by is null or invited_by ~ '^[a-z0-9]{1,12}$')
) not valid;

drop policy if exists "anon can insert" on public.responses;
create policy "anon can insert" on public.responses
  for insert to anon
  with check (
    jsonb_typeof(answers) = 'array'
    and jsonb_array_length(answers) = 10
    and not exists (
      select 1 from jsonb_array_elements(answers) e
      where jsonb_typeof(e) <> 'number' or (e #>> '{}') !~ '^[0-3]$'
    )
  );

-- ۳) محدودیت ثبت: حداکثر ۲۰ پاسخ از هر IP در ۱۰ دقیقه (جلوی اسپم ساده را می‌گیرد)
create index if not exists responses_ip_time_idx on public.responses (ip, created_at);

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
  if new.ip is not null and
     (select count(*) from public.responses
        where ip = new.ip and created_at > now() - interval '10 minutes') >= 20 then
    raise exception 'rate limit exceeded' using errcode = 'P0001';
  end if;
  return new;
end $$;
revoke all on function public.set_request_meta() from public, anon, authenticated;

-- ۴) تابع ادمین فقط برای کاربر واردشده
revoke all on function public.is_admin() from public, anon;
grant execute on function public.is_admin() to authenticated;

-- ۵) ویو فقط برای ادمین
alter view public.referral_counts set (security_invoker = true);
revoke all on public.referral_counts from anon;
grant select on public.referral_counts to authenticated;
