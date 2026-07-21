// @vitest-environment jsdom
import {afterEach,describe,expect,it,vi} from 'vitest';
import React from 'react';
import {act} from 'react';
import {createRoot} from 'react-dom/client';
import App from './App';
import { ThemeProvider } from './theme';
import {api,User,RoleRecord} from './api';

const admin:User={id:1,email:'admin@example.com',role:'admin',disabled:false};
const operator:User={id:2,email:'operator@example.com',role:'operator',disabled:false};
const viewer:User={id:3,email:'viewer@example.com',role:'viewer',disabled:false};
const emptyHosts=vi.fn().mockResolvedValue([]);
const emptyCerts=vi.fn().mockResolvedValue([]);
const customRole:RoleRecord={id:4,slug:'auditor',name:'Auditor',description:'',system_managed:false,permissions:['audit_logs.read']};

async function renderDashboard(user:User,users:User[]=[admin,operator,viewer]) {
  vi.spyOn(api,'status').mockResolvedValue({initialized:true});
  vi.spyOn(api,'me').mockResolvedValue(user);
  vi.spyOn(api,'hosts').mockImplementation(emptyHosts);
  vi.spyOn(api,'certificates').mockImplementation(emptyCerts);
  vi.spyOn(api,'users').mockResolvedValue(users);
  vi.spyOn(api,'roles').mockResolvedValue([customRole]);
  const element=document.createElement('div');document.body.appendChild(element);
  const root=createRoot(element);
  await act(async()=>{root.render(<ThemeProvider><App/></ThemeProvider>);});
  return {element,root};
}

describe('Users API contracts',()=>{
  afterEach(()=>{vi.restoreAllMocks();document.body.innerHTML='';});
  it('lists, creates, updates and deletes users',async()=>{
    const fetchMock=vi.spyOn(globalThis,'fetch').mockImplementation(async(input,init)=>{
      const path=String(input);
      if(path==='/api/users'&&!init?.method)return new Response(JSON.stringify([admin]),{status:200});
      if(path==='/api/users'&&init?.method==='POST')return new Response(JSON.stringify(admin),{status:201});
      if(path==='/api/users/2'&&init?.method==='PATCH')return new Response(JSON.stringify({...operator,role:'viewer'}),{status:200});
      return new Response(null,{status:204});
    });
    await expect(api.users()).resolves.toEqual([admin]);
    await expect(api.createUser({email:admin.email,password:'passwordpassword',role:'admin'})).resolves.toEqual(admin);
    await expect(api.updateUser(2,{role:'viewer'})).resolves.toMatchObject({role:'viewer'});
    await expect(api.deleteUser(2)).resolves.toBeUndefined();
    expect(fetchMock).toHaveBeenCalledTimes(4);
  });
  it('calls role and session administration endpoints',async()=>{
    const fetchMock=vi.spyOn(globalThis,'fetch').mockImplementation(async(input,init)=>{
      const path=String(input);
      if(path==='/api/roles'&&!init?.method)return new Response(JSON.stringify([customRole]),{status:200});
      if(path==='/api/users/2/sessions/revoke')return new Response(JSON.stringify({revoked:2}),{status:200});
      return new Response(JSON.stringify(customRole),{status:200});
    });
    await expect(api.roles()).resolves.toEqual([customRole]);
    await expect(api.revokeUserSessions(2)).resolves.toEqual({revoked:2});
    await expect(api.createRole({slug:'auditor',name:'Auditor',description:'',permissions:['audit_logs.read']})).resolves.toEqual(customRole);
    expect(fetchMock).toHaveBeenCalledTimes(3);
  });
});

describe('Dashboard Users UI',()=>{
  afterEach(()=>{vi.restoreAllMocks();document.body.innerHTML='';});
  it('shows Users only to admins, including disabled status',async()=>{
    const disabled={...viewer,email:'disabled@example.com',disabled:true};
    const adminView=await renderDashboard(admin,[admin,disabled]);
    expect(adminView.element.textContent).toContain('Users');
    expect(adminView.element.textContent).toContain('Roles');
    expect(adminView.element.textContent).toContain('Revoke sessions');
    expect(adminView.element.textContent).toContain('Disabled');
    adminView.root.unmount();document.body.innerHTML='';
    const operatorView=await renderDashboard(operator,[operator]);
    expect(operatorView.element.textContent).not.toContain('Users');
    operatorView.root.unmount();document.body.innerHTML='';
    const viewerView=await renderDashboard(viewer,[viewer]);
    expect(viewerView.element.textContent).not.toContain('Users');
    viewerView.root.unmount();
  });
  it('submits create, role update, and confirmed disable/delete actions',async()=>{
    const created={id:4,email:'new@example.com',role:'viewer' as const,disabled:false};
    const create=vi.spyOn(api,'createUser').mockResolvedValue(created);
    const update=vi.spyOn(api,'updateUser').mockResolvedValue({...operator,role:'viewer'});
    const remove=vi.spyOn(api,'deleteUser').mockResolvedValue(undefined);
    vi.spyOn(window,'confirm').mockReturnValue(true);
    const {element,root}=await renderDashboard(admin,[admin,operator]);
    const inputs=element.querySelectorAll('input');
    await act(async()=>{const set=Object.getOwnPropertyDescriptor(HTMLInputElement.prototype,'value')!.set!;set.call(inputs[4],'new@example.com');inputs[4].dispatchEvent(new Event('input',{bubbles:true}));set.call(inputs[5],'long-password-123');inputs[5].dispatchEvent(new Event('input',{bubbles:true}));});
    const form=element.querySelector('.user-form') as HTMLFormElement;
    await act(async()=>{form.dispatchEvent(new Event('submit',{bubbles:true,cancelable:true}));});
    expect(create).toHaveBeenCalledWith({email:'new@example.com',password:'long-password-123',role:'viewer'});
    const selects=element.querySelectorAll('select');
    expect(selects.length).toBeGreaterThanOrEqual(3);
    const buttons=[...element.querySelectorAll('button')].filter(button=>button.textContent==='Disable'||button.textContent==='Delete') as HTMLButtonElement[];
    await act(async()=>{buttons[0].click();buttons[1].click();});
    expect(update).toHaveBeenCalledWith(2,{disabled:true});
    expect(remove).toHaveBeenCalledWith(2);
    root.unmount();
  });
  it('uses safe generic errors for user loading and mutations',async()=>{
    const usersLoad=vi.spyOn(api,'users');
    const view=await renderDashboard(admin,[admin]);
    usersLoad.mockRejectedValue(new Error('500 internal stack token=secret-value'));
    const refresh=view.element.querySelector('.users-card button') as HTMLButtonElement;
    await act(async()=>{refresh.click();});
    expect(view.element.textContent).not.toContain('internal stack');
    expect(view.element.textContent).toContain('Unable to complete the user request. Please try again.');
    expect(view.element.textContent).not.toContain('internal stack');
    usersLoad.mockResolvedValue([admin,operator]);
    await act(async()=>{refresh.click();});
    const update=vi.spyOn(api,'updateUser').mockRejectedValue(new Error('database password=super-secret'));
    const select=view.element.querySelectorAll('tbody select')[1] as HTMLSelectElement;
    await act(async()=>{select.value='viewer';select.dispatchEvent(new Event('change',{bubbles:true}));});
    expect(update).toHaveBeenCalledWith(2,{role:'viewer'});
    expect(view.element.textContent).toContain('Unable to complete the user request. Please try again.');
    expect(view.element.textContent).not.toContain('super-secret');
    view.root.unmount();
  });
});
