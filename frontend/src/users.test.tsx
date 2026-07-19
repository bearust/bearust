// @vitest-environment jsdom
import {afterEach,describe,expect,it,vi} from 'vitest';
import React from 'react';
import {act} from 'react';
import {createRoot} from 'react-dom/client';
import {api,User} from './api';
import {UsersSection} from './App';

const admin:User={id:1,email:'admin@example.com',role:'admin',disabled:false};
const operator:User={id:2,email:'operator@example.com',role:'operator',disabled:false};

describe('Users API contracts',()=>{
  afterEach(()=>vi.restoreAllMocks());
  it('lists, creates, updates and deletes users',async()=>{
    const fetchMock=vi.spyOn(globalThis,'fetch').mockImplementation(async (input,init)=>{
      const path=String(input);
      if(path==='/api/users' && !init?.method) return new Response(JSON.stringify([admin]),{status:200});
      if(path==='/api/users' && init?.method==='POST') return new Response(JSON.stringify(admin),{status:201});
      if(path==='/api/users/2' && init?.method==='PATCH') return new Response(JSON.stringify({...operator,role:'viewer'}),{status:200});
      return new Response(null,{status:204});
    });
    await expect(api.users()).resolves.toEqual([admin]);
    await expect(api.createUser({email:admin.email,password:'passwordpassword',role:'admin'})).resolves.toEqual(admin);
    await expect(api.updateUser(2,{role:'viewer'})).resolves.toMatchObject({role:'viewer'});
    await expect(api.deleteUser(2)).resolves.toBeUndefined();
    expect(fetchMock).toHaveBeenCalledTimes(4);
  });
});

describe('Users section',()=>{
  afterEach(()=>vi.restoreAllMocks());
  it('is absent for non-admin roles',()=>{
    const rootEl=document.createElement('div'); document.body.appendChild(rootEl); const root=createRoot(rootEl);
    act(()=>{root.render(<UsersSection user={operator} users={[]} onChanged={()=>{}}/>)});
    expect(rootEl.textContent).toBe('');
    root.unmount();
  });
  it('renders status and creates a user for an admin',async()=>{
    const created:User={id:3,email:'disabled@example.com',role:'viewer',disabled:true};
    vi.spyOn(api,'createUser').mockResolvedValue(created);
    const rootEl=document.createElement('div'); document.body.appendChild(rootEl); const root=createRoot(rootEl);
    await act(async()=>{root.render(<UsersSection user={admin} users={[admin,created]} onChanged={()=>{}}/>)});
    expect(rootEl.textContent).toContain('disabled@example.com');
    expect(rootEl.textContent).toContain('Disabled');
    await api.createUser({email:'new@example.com',password:'passwordpassword',role:'viewer'});
    expect(api.createUser).toHaveBeenCalled();
    root.unmount();
  });
  it('shows safe errors for forbidden and validation responses',async()=>{
    vi.spyOn(api,'updateUser').mockRejectedValue(new Error('403 Forbidden: internal stack token=secret'));
    const rootEl=document.createElement('div'); document.body.appendChild(rootEl); const root=createRoot(rootEl);
    await act(async()=>{root.render(<UsersSection user={admin} users={[operator]} onChanged={()=>{}}/>)});
    const roleSelect=rootEl.querySelector('select')! as HTMLSelectElement;
    roleSelect.value='viewer';
    await act(async()=>{roleSelect.dispatchEvent(new Event('change',{bubbles:true}));});
    expect(rootEl.textContent).not.toContain('internal stack');
    root.unmount();
  });
});
