import type { FastifyInstance } from 'fastify';
import { z } from 'zod';
import { inRequestTransaction, requestDatabase } from '../db.js';
import { AppError } from '../errors.js';
import { decodeCursor, encodeCursor } from '../cursor.js';
import { auditStaffAccess, auditStaffAccessMany } from './internal-audit.js';
import { parseInput, parsePageSize, requireSecurityStaff, requireUser, uuidSchema } from '../validation.js';

const idParams = z.object({ id: uuidSchema });
const statusLabels: Record<string, string> = { received: 'Received', reviewing: 'Under review', actioned: 'Action taken', closed: 'Closed' };
const submissionSchema = z.object({
  category: z.enum(['security', 'privacy']),
  summary: z.string().trim().min(5).max(200),
  details: z.string().trim().min(10).max(5000),
  affectedFlow: z.string().trim().max(160).optional(),
  impact: z.string().trim().max(1000).optional(),
}).strict();
const listQuery = z.object({ status: z.enum(['received', 'reviewing', 'actioned', 'closed']).optional(), cursor: z.string().max(512).optional(), limit: z.unknown().optional() });
const updateSchema = z.object({
  status: z.enum(['reviewing', 'actioned', 'closed']),
  resolution: z.string().trim().max(1000).nullable().optional(),
  recurrenceKey: z.string().trim().toLowerCase().regex(/^[a-z0-9][a-z0-9._:-]{1,119}$/).nullable().optional(),
}).strict();
const metricsQuery = z.object({ days: z.coerce.number().int().min(1).max(180).default(30) });

export async function registerSecurityReportRoutes(app: FastifyInstance): Promise<void> {
  app.post('/api/v1/security-reports', { config: { authRequired: true, rateLimitMax: 2, rateLimitWindowMs: 3_600_000 } }, async (request, reply) => {
    const user = requireUser(request);
    const input = parseInput(submissionSchema, request.body);
    const result = await requestDatabase(request).query<{ id: string; createdAt: Date | string }>(
      `INSERT INTO security_reports (reporter_id,category,summary,details,affected_flow,impact,expires_at)
       VALUES ($1,$2,$3,$4,$5,$6,now()+($7::int*interval '1 day'))
       RETURNING id,created_at AS "createdAt"`,
      [user.id, input.category, input.summary, input.details, input.affectedFlow ?? null, input.impact ?? null,
        app.config.SECURITY_REPORT_RETENTION_DAYS],
    );
    const row = result.rows[0];
    if (!row) throw new AppError(503, 'REPORT_UNAVAILABLE', 'The report could not be saved.');
    reply.code(201);
    return { data: { caseId: row.id, status: 'received', statusLabel: statusLabels.received,
      statusUrl: `/api/v1/me/security-reports/${row.id}`, createdAt: row.createdAt } };
  });

  app.get('/api/v1/me/security-reports/:id', { config: { authRequired: true } }, async (request) => {
    const user = requireUser(request);
    const { id } = parseInput(idParams, request.params);
    const result = await requestDatabase(request).query<{ id: string; status: string; createdAt: Date | string; updatedAt: Date | string }>(
      `SELECT id,status,created_at AS "createdAt",updated_at AS "updatedAt" FROM security_reports
       WHERE id=$1 AND reporter_id=$2 AND expires_at>now()`, [id, user.id],
    );
    const row = result.rows[0];
    if (!row) throw new AppError(404, 'NOT_FOUND', 'Security/privacy case not found.');
    return { data: { caseId: row.id,status: row.status,statusLabel: statusLabels[row.status] ?? 'Received',
      statusUrl: `/api/v1/me/security-reports/${row.id}`,createdAt: row.createdAt,updatedAt: row.updatedAt } };
  });

  app.get('/api/v1/internal/security-reports', { config: { authRequired: true } }, async (request) => {
    const staff = requireSecurityStaff(request);
    const query = parseInput(listQuery, request.query);
    const limit = parsePageSize(query.limit);
    const cursor = decodeCursor(query.cursor);
    const params: unknown[] = [];
    const conditions = ['expires_at>now()'];
    if (query.status) { params.push(query.status); conditions.push(`status=$${params.length}`); }
    if (cursor) {
      params.push(cursor.createdAt,cursor.id);
      conditions.push(`(created_at,id)<($${params.length-1}::timestamptz,$${params.length}::uuid)`);
    }
    params.push(limit+1);
    const result = await requestDatabase(request).query<{ id: string; category: string; status: string; createdAt: Date | string }>(
      `SELECT id,category,status,created_at AS "createdAt" FROM security_reports
       WHERE ${conditions.join(' AND ')} ORDER BY created_at DESC,id DESC LIMIT $${params.length}`,params,
    );
    const hasMore = result.rows.length>limit;
    const rows = result.rows.slice(0,limit);
    await auditStaffAccessMany(requestDatabase(request),staff.id,'security_report.read',rows.map((row)=>row.id));
    const last=rows.at(-1);
    return { data: rows.map((row)=>({...row,statusLabel:statusLabels[row.status]??'Received',statusUrl:`/api/v1/internal/security-reports/${row.id}`})),
      page:{hasMore,nextCursor:hasMore&&last?encodeCursor({createdAt:new Date(last.createdAt).toISOString(),id:last.id}):null} };
  });

  app.get('/api/v1/internal/security-reports/metrics', { config: { authRequired: true } }, async (request) => {
    const staff = requireSecurityStaff(request);
    const { days } = parseInput(metricsQuery,request.query);
    await auditStaffAccess(requestDatabase(request),staff.id,'security_report.metrics_read',null,{days});
    const byCategory=await requestDatabase(request).query(
      `SELECT category,count(*)::int AS volume,
         round(avg(extract(epoch FROM(first_response_at-created_at)))::numeric,1) AS "avgFirstResponseSeconds",
         sum(reopen_count)::int AS "reopenedCases"
       FROM security_reports WHERE created_at>=now()-($1::int*interval '1 day') GROUP BY category ORDER BY volume DESC`,[days],
    );
    const recurring=await requestDatabase(request).query(
      `SELECT recurrence_key AS "recurrenceKey",count(*)::int AS volume FROM security_reports
       WHERE recurrence_key IS NOT NULL AND created_at>=now()-($1::int*interval '1 day')
       GROUP BY recurrence_key ORDER BY volume DESC LIMIT 10`,[days],
    );
    return {data:{windowDays:days,byCategory:byCategory.rows,recurringCases:recurring.rows}};
  });

  app.get('/api/v1/internal/security-reports/:id', { config: { authRequired: true } }, async (request) => {
    const staff=requireSecurityStaff(request);
    const {id}=parseInput(idParams,request.params);
    const result=await requestDatabase(request).query(
      `SELECT id,category,summary,details,affected_flow AS "affectedFlow",impact,status,
         recurrence_key AS "recurrenceKey",created_at AS "createdAt"
       FROM security_reports WHERE id=$1 AND expires_at>now()`,[id],
    );
    const row=result.rows[0];
    if(!row) throw new AppError(404,'NOT_FOUND','Security/privacy case not found.');
    await auditStaffAccess(requestDatabase(request),staff.id,'security_report.read',id);
    return {data:row};
  });

  app.patch('/api/v1/internal/security-reports/:id', { config: { authRequired: true, rateLimitMax: 30 } }, async (request) => {
    const staff=requireSecurityStaff(request);
    const {id}=parseInput(idParams,request.params);
    const input=parseInput(updateSchema,request.body);
    return {data:await inRequestTransaction(request, async(client)=>{
      const current=await client.query<{status:string}>('SELECT status FROM security_reports WHERE id=$1 AND expires_at>now() FOR UPDATE',[id]);
      const prior=current.rows[0]?.status;
      if(!prior) throw new AppError(404,'NOT_FOUND','Security/privacy case not found.');
      if(!allowedTransition(prior,input.status)) throw new AppError(409,'INVALID_STATE','Report status cannot move to that state.');
      const updated=await client.query(
        `UPDATE security_reports SET status=$2::internal_report_status,resolution=CASE WHEN $3::boolean THEN $4::varchar ELSE resolution END,
           recurrence_key=CASE WHEN $5::boolean THEN $6::varchar ELSE recurrence_key END,reviewed_by=$7,updated_at=now(),
           first_response_at=COALESCE(first_response_at,CASE WHEN $2::internal_report_status<>'received'::internal_report_status THEN now() END),
           reopen_count=reopen_count+CASE WHEN status='closed' AND $2::internal_report_status='reviewing'::internal_report_status THEN 1 ELSE 0 END
         WHERE id=$1 RETURNING id,status,updated_at AS "updatedAt",reopen_count AS "reopenCount"`,
        [id,input.status,input.resolution!==undefined,input.resolution??null,input.recurrenceKey!==undefined,input.recurrenceKey??null,staff.id],
      );
      await client.query(
        `INSERT INTO staff_access_audit(staff_id,event_type,resource_id,metadata)
         VALUES($1,'security_report.status_changed',$2,$3::jsonb)`,
        [staff.id,id,JSON.stringify({from:prior,to:input.status})],
      );
      return updated.rows[0];
    })};
  });
}

function allowedTransition(from:string,to:string):boolean{
  if(from===to)return true;
  if(from==='received')return to==='reviewing'||to==='closed';
  if(from==='reviewing')return to==='actioned'||to==='closed';
  if(from==='actioned')return to==='closed';
  if(from==='closed')return to==='reviewing';
  return false;
}
